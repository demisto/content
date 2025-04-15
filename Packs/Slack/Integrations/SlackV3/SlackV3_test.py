import json as js
import threading
from unittest.mock import MagicMock

import aiohttp
import pytest
import slack_sdk
from slack_sdk.errors import SlackApiError
from slack_sdk.web.async_slack_response import AsyncSlackResponse
from slack_sdk.web.slack_response import SlackResponse

from SlackV3 import get_war_room_url, parse_common_channels

from CommonServerPython import *


def load_test_data(path):
    with open(path, encoding='utf-8') as f:
        return f.read()


CHANNELS = load_test_data('./test_data/channels.txt')
USERS = load_test_data('./test_data/users.txt')
CONVERSATIONS = load_test_data('./test_data/conversations.txt')
MESSAGES = load_test_data('./test_data/messages.txt')
PAYLOAD_JSON = load_test_data('./test_data/payload.txt')
INTEGRATION_CONTEXT: dict

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

SLACK_RESPONSE = SlackResponse(client=None, http_verb='', api_url='', req_args={}, data={'ts': 'cool'}, headers={},
                               status_code=0)
SLACK_RESPONSE_2 = SlackResponse(client=None, http_verb='', api_url='', req_args={}, data={'cool': 'cool'}, headers={},
                                 status_code=0)

INBOUND_MESSAGE_FROM_BOT = {
    "token": "HRaWNBI1UXkKjvIntY29juPo",
    "team_id": "TABQMPKP0",
    "api_app_id": "A01TXQAGB2P",
    "event": {
        "type": "message",
        "subtype": "bot_message",
        "text": "This is a bot message\nView it on: <https://somexsoarserver.com#/home>",
        "ts": "1644999987.969789",
        "username": "I'm a BOT",
        "icons": {
            "image_48": "https://someimage.png"
        },
        "bot_id": "B01UZHGMQ9G",
        "channel": "C033HLL3N81",
        "event_ts": "1644999987.969789",
        "channel_type": "group"
    },
    "type": "event_callback",
    "event_id": "Ev0337CL1P0D",
    "event_time": 1644999987,
    "authorizations": [{
        "enterprise_id": None,
        "team_id": "TABQMPKP0",
        "user_id": "U0209BPNFC0",
        "is_bot": True,
        "is_enterprise_install": False
    }],
    "is_ext_shared_channel": False,
    "event_context": "4-eyJldCI6Im1lc3NhZ2UiLCJ0aWQiOiJUQUJRTVBLUDAiLCJhaWQiOiJBMDFUWFFBR0IyUCIsImNpZCI6IkMwMzNITEwzTjgxIn0"
}

INBOUND_MESSAGE_FROM_USER = {
    "token": "HRaWNBI1UXkKjvIntY29juPo",
    "user": {'id': "ZSADAD12"},
    "team_id": "TABQMPKP0",
    "api_app_id": "A01TXQAGB2P",
    "event": {
        "client_msg_id": "72a28a3b-fb06-4137-ac95-40d35fb6b08c",
        "type": "message",
        "text": "This is not from a bot.",
        "user": "UAALZT5D2",
        "ts": "1645000777.157199",
        "team": "TABQMPKP0",
        "blocks": [{
            "type": "rich_text",
            "block_id": "7jEsM",
            "elements": [{
                "type": "rich_text_section",
                "elements": [{
                    "type": "text",
                    "text": "This is not from a bot."
                }]
            }]
        }],
        "channel": "C033HLL3N81",
        "event_ts": "1645000777.157199",
        "channel_type": "group"
    },
    "type": "event_callback",
    "event_id": "Ev033ABZ2TBM",
    "event_time": 1645000777,
    "authorizations": [{
        "enterprise_id": None,
        "team_id": "TABQMPKP0",
        "user_id": "U0209BPNFC0",
        "is_bot": True,
        "is_enterprise_install": False
    }],
    "is_ext_shared_channel": False,
    "event_context": "4-eyJldCI6Im1lc3NhZ2UiLCJ0aWQiOiJUQUJRTVBLUDAiLCJhaWQiOiJBMDFUWFFBR0IyUCIsImNpZCI6IkMwMzNITEwzTjgxIn0"
}


INBOUND_MESSAGE_FROM_BOT_WITH_BOT_ID = {
    "token": "HRaWNBI1UXkKjvIntY29juPo",
    "team_id": "TABQMPKP0",
    "api_app_id": "A01TXQAGB2P",
    "event": {
        "type": "message",
        "subtype": "This is missing",
        "text": "This is a bot message\nView it on: <https://somexsoarserver.com#/home>",
        "ts": "1644999987.969789",
        "username": "I'm a BOT",
        "icons": {
            "image_48": "https://someimage.png"
        },
        "bot_id": "W12345678",
        "channel": "C033HLL3N81",
        "event_ts": "1644999987.969789",
        "channel_type": "group"
    },
    "type": "event_callback",
    "event_id": "Ev0337CL1P0D",
    "event_time": 1644999987,
    "is_ext_shared_channel": False,
    "event_context": "4-eyJldCI6Im1lc3NhZ2UiLCJ0aWQiOiJUQUJRTVBLUDAiLCJhaWQiOiJBMDFUWFFBR0IyUCIsImNpZCI6IkMwMzNITEwzTjgxIn0"
}

INBOUND_EVENT_MESSAGE = {
    "envelope_id": "d515b90f-ba7f-425d-a1b2-b4fb4f0f0e2b",
    "payload": {
        "type": "block_actions",
        "user": {
            "id": "U01A5FGR0BT",
            "username": "test",
            "name": "test",
            "team_id": "T019C4MM2VD"
        },
        "api_app_id": "123",
        "token": "123",
        "container": {
            "type": "message",
            "message_ts": "1645712173.407939",
            "channel_id": "G01FZSE6HCG",
            "is_ephemeral": False
        },
        "trigger_id": "3165963195265.1318157716999.f90b6e19a46a36ca5d2d76c77095748b",
        "team": {
            "id": "Test",
            "domain": "test"
        },
        "enterprise": None,
        "is_enterprise_install": False,
        "channel": {
            "id": "G01FZSE6HCG",
            "name": "test"
        },
        "message": {
            "type": "message",
            "subtype": "bot_message",
            "text": "Hi",
            "ts": "1645712173.407939",
            "username": "test",
            "icons": {
                "image_48": "https://s3-us-west-2.amazonaws.com/slack-files2/bot_icons/2021-07-14/2273797940146_48.png"
            },
            "bot_id": "B0342JWALTG",
            "blocks": [{
                "type": "section",
                "block_id": "VpQ0F",
                "text": {
                    "type": "mrkdwn",
                    "text": "Hi",
                    "verbatim": False
                }
            }, {
                "type": "actions",
                "block_id": "06eO",
                "elements": [{
                    "type": "button",
                    "action_id": "o2pI",
                    "text": {
                        "type": "plain_text",
                        "text": "Yes",
                        "emoji": True
                    },
                    "style": "primary",
                    "value": "{\"entitlement\": \"8e8798e0-5f49-4dcd-85de-cf2c2b13bc3a@2200|57\", \"reply\": \"Hi\"}"
                }, {
                    "type": "button",
                    "action_id": "CdRu",
                    "text": {
                        "type": "plain_text",
                        "text": "No",
                        "emoji": True
                    },
                    "style": "danger",
                    "value": "{\"entitlement\": \"8e8798e0-5f49-4dcd-85de-cf2c2b13bc3a@2200|57\", \"reply\": \"Hi\"}"
                }]
            }]
        },
        "state": {
            "values": {}
        },
        "response_url": "https://hooks.slack.com/actions/T019C4MM2VD/3146697353558/Y6ic5jAvlJ6p9ZU9HmyU9sPZ",
        "actions": [{
            "action_id": "o2pI",
            "block_id": "06eO",
            "text": {
                "type": "plain_text",
                "text": "Yes",
                "emoji": True
            },
            "value": "{\"entitlement\": \"8e8798e0-5f49-4dcd-85de-cf2c2b13bc3a@2200|57\", \"reply\": \"Hi\"}",
            "style": "primary",
            "type": "button",
            "action_ts": "1645712301.478754"
        }]
    },
    "type": "interactive",
    "accepts_response_payload": False
}

INBOUND_MESSAGE_FROM_BOT_WITHOUT_USER_ID = {
    "token": "HRaWNBI1UXkKjvIntY29juPo",
    "team_id": "TABQMPKP0",
    "api_app_id": "A01TXQAGB2P",
    "event": {
        "type": "message",
        "text": "This is a bot message\nView it on: <https:\/\/somexsoarserver.com#\/home>",
        "ts": "1644999987.969789",
        "username": "I'm a BOT",
        "icons": {
            "image_48": "https:\/\/someimage.png"
        },
        "bot_id": "B01UZHGMQ9G",
        "channel": "C033HLL3N81",
        "event_ts": "1644999987.969789",
        "channel_type": "group"
    },
    "type": "event_callback",
    "event_id": "Ev0337CL1P0D",
    "event_time": 1644999987,
    "authorizations": [{
        "enterprise_id": None,
        "team_id": "TABQMPKP0",
        "user_id": "U0209BPNFC0",
        "is_bot": True,
        "is_enterprise_install": False
    }],
    "is_ext_shared_channel": False,
    "event_context": "4-eyJldCI6Im1lc3NhZ2UiLCJ0aWQiOiJUQUJRTVBLUDAiLCJhaWQiOiJBMDFUWFFBR0IyUCIsImNpZCI6IkMwMzNITEwzTjgxIn0"
}

SIMPLE_USER_MESSAGE = {
    "token": "d8on5ZZu1q907qYxV65stnfx",
    "team_id": "team_id",
    "context_team_id": "context_team_id",
    "context_enterprise_id": None,
    "api_app_id": "api_app_id",
    "event": {
        "client_msg_id": "6af5a984-e50c-426f-abf0-d42c2246a9d1",
        "type": "message",
        "text": "messgae from user test_1",
        "user": "USER_USER_1",
        "ts": "1681650557.769109",
        "blocks": [
            {
                "type": "rich_text",
                "block_id": "UgHdS",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": "messgae from user test_1"
                            }
                        ]
                    }
                ]
            }
        ],
        "team": "ABCDFCFRTGY",
        "channel": "ABCDFCFRTGR",
        "event_ts": "1681650557.769109",
        "channel_type": "group"
    },
    "type": "event_callback",
    "event_id": "event_id",
    "event_time": 1681650557,
    "authorizations": [
        {
            "enterprise_id": None,
            "team_id": "team_id",
            "user_id": "user_id",
            "is_bot": True,
            "is_enterprise_install": False
        }
    ],
    "is_ext_shared_channel": False,
    "event_context": "event_context"
}


def test_exception_in_invite_to_mirrored_channel(mocker):
    import SlackV3
    from SlackV3 import check_for_mirrors
    new_user = {
        'name': 'perikles',
        'profile': {
            'email': 'perikles@acropoli.com',
        },
        'id': 'U012B3CUI'
    }

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        users = {'members': js.loads(USERS)}
        users['members'].append(new_user)
        return users

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

    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'mirrorInvestigation', return_value=[{'email': 'spengler@ghostbusters.example.com',
                                                                       'username': 'spengler'},
                                                                      {'email': 'perikles@acropoli.com',
                                                                       'username': 'perikles'}])
    mocker.patch.object(SlackV3, 'invite_to_mirrored_channel', side_effect=Exception)
    mocker.patch.object(demisto, 'error')
    SlackV3.CACHE_EXPIRY = EXPIRED_TIMESTAMP
    check_for_mirrors()
    assert demisto.setIntegrationContext.call_count != 0
    assert demisto.error.call_args[0][0] == 'Could not invite investigation users to the mirrored channel: '


def get_integration_context():
    return INTEGRATION_CONTEXT


def set_integration_context(integration_context):
    global INTEGRATION_CONTEXT
    INTEGRATION_CONTEXT = integration_context


RETURN_ERROR_TARGET = 'SlackV3.return_error'


@pytest.fixture(autouse=True)
def setup(mocker):
    import SlackV3

    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'debug')

    set_integration_context({
        'mirrors': MIRRORS,
        'users': USERS,
        'conversations': CONVERSATIONS,
        'bot_id': 'W12345678'
    })

    SlackV3.init_globals()
    # We will manually change the caching mode to ensure it doesn't break previous user's envs.
    SlackV3.ENABLE_CACHING = False


class AsyncMock(MagicMock):
    async def __call__(self, *args, **kwargs):
        return super().__call__(*args, **kwargs)


@pytest.mark.asyncio
async def test_get_slack_name_user(mocker):
    from SlackV3 import get_slack_name

    async def users_info(user: str):
        if user != 'alexios':
            return js.loads(USERS)[0]
        return None

    async def conversations_info():
        return {'channel': js.loads(CONVERSATIONS)[0]}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext')

    #
    socket_client = AsyncMock()
    mocker.patch.object(socket_client, 'users_info', side_effect=users_info)
    mocker.patch.object(socket_client, 'conversations_info', side_effect=conversations_info)
    # Assert 6516

    # User in integration context
    user_id = 'U012A3CDE'
    name = await get_slack_name(user_id, socket_client)
    assert name == 'spengler'
    assert socket_client.call_count == 0

    # User not in integration context
    unknown_user = 'USASSON'
    name = await get_slack_name(unknown_user, socket_client)
    assert name == 'spengler'
    assert socket_client.users_info.call_count == 1

    # User does not exist
    nonexisting_user = 'alexios'
    name = await get_slack_name(nonexisting_user, socket_client)
    assert name == ''
    assert socket_client.users_info.call_count == 1


@pytest.mark.asyncio
async def test_get_slack_name_channel(mocker):
    from SlackV3 import get_slack_name

    # Set

    async def users_info(user: str):
        if user != 'alexios':
            return js.loads(USERS)[0]
        return None

    async def conversations_info(channel=''):
        return js.loads(CONVERSATIONS)[0]

    socket_client = AsyncMock()

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(socket_client, 'users_info', side_effect=users_info)
    mocker.patch.object(socket_client, 'conversations_info',
                        side_effect=conversations_info)

    # Assert

    # Channel in integration context
    channel_id = 'C012AB3CD'
    name = await get_slack_name(channel_id, socket_client)
    assert name == 'general'
    assert socket_client.api_call.call_count == 0

    # Channel not in integration context
    unknown_channel = 'CSASSON'
    name = await get_slack_name(unknown_channel, socket_client)
    assert name == 'general'
    assert socket_client.conversations_info.call_count == 1

    # Channel doesn't exist
    nonexisting_channel = 'lulz'
    name = await get_slack_name(nonexisting_channel, socket_client)
    assert name == ''
    assert socket_client.conversations_info.call_count == 1


@pytest.mark.asyncio
async def test_clean_message(mocker):
    from SlackV3 import clean_message

    # Set
    async def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.info':
            return {'user': js.loads(USERS)[0]}
        elif method == 'conversations.info':
            return {'channel': js.loads(CONVERSATIONS)[0]}
        return None

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

    user_message = 'Hello <@U012A3CDE>!'
    channel_message = 'Check <#C012AB3CD>'
    link_message = 'Go to <https://www.google.com/lulz>'

    # Arrange

    clean_user_message = await clean_message(user_message, slack_sdk.WebClient)
    clean_channel_message = await clean_message(channel_message, slack_sdk.WebClient)
    clean_link_message = await clean_message(link_message, slack_sdk.WebClient)

    # Assert

    assert clean_user_message == 'Hello spengler!'
    assert clean_channel_message == 'Check general'
    assert clean_link_message == 'Go to https://www.google.com/lulz'


class TestGetConversationByName:
    @staticmethod
    def set_conversation_mock(mocker, get_context=get_integration_context):
        mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_context)
        mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
        mocker.patch.object(slack_sdk.WebClient, 'api_call', return_value={'channels': js.loads(CONVERSATIONS)})

    def test_get_conversation_by_name_exists_in_context(self, mocker):
        """
        Given:
        - Conversation to find

        When:
        - Conversation exists in context

        Then:
        - Check if the right conversation returned
        - Check that no API command was called.
        """
        from SlackV3 import get_conversation_by_name
        self.set_conversation_mock(mocker)

        conversation_name = 'general'
        conversation = get_conversation_by_name(conversation_name)

        # Assertions
        assert conversation_name == conversation['name']
        assert slack_sdk.WebClient.api_call.call_count == 0

    def test_get_conversation_by_name_exists_in_api_call(self, mocker):
        """
        Given:
        - Conversation to find

        When:
        - Conversation not exists in context, but do in the API

        Then:
        - Check if the right conversation returned
        - Check that a API command was called.
        """

        def get_context():
            return {}

        from SlackV3 import get_conversation_by_name

        self.set_conversation_mock(mocker, get_context=get_context)

        conversation_name = 'general'
        conversation = get_conversation_by_name(conversation_name)

        # Assertions
        assert conversation_name == conversation['name']
        assert slack_sdk.WebClient.api_call.call_count == 1

        # Find that 'general' conversation has been added to context
        conversations = json.loads(demisto.setIntegrationContext.call_args[0][0]['conversations'])
        filtered = list(filter(lambda c: c['name'] == conversation_name, conversations))
        assert filtered, 'Could not find the \'general\' conversation in the context'

    def test_get_conversation_by_name_not_exists(self, mocker):
        """
        Given:
        - Conversation to find

        When:
        - Conversation do not exists.

        Then:
        - Check no conversation was returned.
        - Check that a API command was called.
        """
        from SlackV3 import get_conversation_by_name
        self.set_conversation_mock(mocker)

        conversation_name = 'no exists'
        conversation = get_conversation_by_name(conversation_name)
        assert not conversation
        assert slack_sdk.WebClient.api_call.call_count == 1


def test_get_user_by_name(mocker):
    from SlackV3 import get_user_by_name
    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        new_user = {
            'name': 'perikles',
            'profile': {
                'email': 'perikles@acropoli.com',
                'display_name': 'Dingus',
                'real_name': 'Lingus'
            },
            'id': 'U012B3CUI'
        }
        if method == 'users.list':
            users = {'members': js.loads(USERS)}
            users['members'].append(new_user)
            return users
        elif method == 'users.lookupByEmail':
            return {'user': new_user}
        return None

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

    # Assert
    # User name exists in integration context
    username = 'spengler'
    user = get_user_by_name(username)
    assert user['id'] == 'U012A3CDE'
    assert slack_sdk.WebClient.api_call.call_count == 0

    # User email exists in integration context
    email = 'spengler@ghostbusters.example.com'
    user = get_user_by_name(email)
    assert user['id'] == 'U012A3CDE'
    assert slack_sdk.WebClient.api_call.call_count == 0

    # User name doesn't exist in integration context
    username = 'perikles'
    user = get_user_by_name(username)
    assert user['id'] == 'U012B3CUI'
    assert slack_sdk.WebClient.api_call.call_count == 1

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
    assert slack_sdk.WebClient.api_call.call_count == 2

    # User doesn't exist
    username = 'alexios'
    user = get_user_by_name(username)
    assert user == {}
    assert slack_sdk.WebClient.api_call.call_count == 3


def test_get_user_by_name_caching_disabled(mocker):
    """
    Given:
        Test Case 1 - User's name only
        Test Case 2 - A user's valid email
        Test Case 3 - A user's valid email which is not in Slack.
    When:
        Searching for a user's ID
    Then:
        Test Case 1 - Assert that only an empty dict was returned and the API was not called.
        Test Case 2 - Assert That the user's ID was found in the returned dict.
        Test Case 3 - Assert that only an empty dict was returned
    """
    import SlackV3
    # Set

    user_1 = {'user': js.loads(USERS)[0]}
    user_2 = {'user': {}}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=[user_1, user_2])

    SlackV3.DISABLE_CACHING = True
    # Assert
    # User name exists in integration context
    username = 'spengler'
    user = SlackV3.get_user_by_name(username)
    assert user == {}
    assert slack_sdk.WebClient.api_call.call_count == 0

    # User email exists in Slack API
    email = 'spengler@ghostbusters.example.com'
    user = SlackV3.get_user_by_name(email)
    assert user['id'] == 'U012A3CDE'
    assert slack_sdk.WebClient.api_call.call_count == 1

    # User email doesn't exist in Slack API
    email = 'perikles@acropoli.com'
    user = SlackV3.get_user_by_name(email)
    assert user == {}
    assert slack_sdk.WebClient.api_call.call_count == 2


def test_get_user_by_name_paging(mocker):
    from SlackV3 import get_user_by_name
    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
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
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

    # Arrange
    user = get_user_by_name('alexios')
    args = slack_sdk.WebClient.api_call.call_args_list
    first_args = args[0][1]
    second_args = args[1][1]

    # Assert
    assert len(first_args['params']) == 1
    assert first_args['params']['limit'] == 200
    assert len(second_args['params']) == 2
    assert second_args['params']['cursor'] == 'dGVhbTpDQ0M3UENUTks='
    assert user['id'] == 'U248918AB'
    assert slack_sdk.WebClient.api_call.call_count == 2


def test_mirror_investigation_new_mirror(mocker):
    from SlackV3 import mirror_investigation

    # Set
    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        if method == 'conversations.create':
            if 'is_private' not in json:
                return {'channel': {
                    'id': 'new_channel', 'name': 'incident-999'
                }}
            return {'channel': {
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
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

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
    success_results = demisto.results.call_args_list[0][0]

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    new_conversations = js.loads(new_context['conversations'])
    our_conversation_filter = list(filter(lambda c: c['id'] == 'new_group', new_conversations))
    our_conversation = our_conversation_filter[0]
    our_mirror_filter = list(filter(lambda m: m['investigation_id'] == '999', new_mirrors))
    our_mirror = our_mirror_filter[0]

    # Assert

    calls = slack_sdk.WebClient.api_call.call_args_list

    groups_call = [c for c in calls if c[0][0] == 'conversations.create']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']
    chat_call = [c for c in calls if c[0][0] == 'chat.postMessage']

    message_args = chat_call[0][1]['json']

    assert len(groups_call) == 1
    assert len(invite_call) == 1
    assert len(topic_call) == 1
    assert len(chat_call) == 1

    assert success_results[0] == 'Investigation mirrored successfully, channel: incident-999'
    assert message_args['channel'] == 'new_group'
    assert message_args['text'] == 'This channel was created to mirror incident 999.' \
                                   ' \n View it on: https://www.eizelulz.com:8443#/WarRoom/999'

    assert len(our_conversation_filter) == 1
    assert len(our_mirror_filter) == 1
    assert our_conversation == {'id': 'new_group', 'name': 'incident-999'}
    assert our_mirror == new_mirror


def test_mirror_investigation_new_mirror_with_name_and_private(mocker):
    from SlackV3 import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        if method == 'conversations.create':
            if 'is_private' not in json:
                return {'channel': {
                    'id': 'new_channel', 'name': 'coolname'
                }}
            return {'channel': {
                'id': 'new_group', 'name': 'coolname'
            }}
        else:
            return {}

    mocker.patch.object(demisto, 'args', return_value={'channelName': 'coolname', 'private': 'true'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '999', 'users': ['spengler', 'alexios']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'https://www.eizelulz.com:8443'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

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
    success_results = demisto.results.call_args_list[0][0]

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    new_conversations = js.loads(new_context['conversations'])
    our_conversation_filter = list(filter(lambda c: c['id'] == 'new_group', new_conversations))
    our_conversation = our_conversation_filter[0]
    our_mirror_filter = list(filter(lambda m: m['investigation_id'] == '999', new_mirrors))
    our_mirror = our_mirror_filter[0]

    # Assert

    calls = slack_sdk.WebClient.api_call.call_args_list

    groups_call = [c for c in calls if c[0][0] == 'conversations.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']
    chat_call = [c for c in calls if c[0][0] == 'chat.postMessage']

    message_args = chat_call[0][1]['json']
    group_args = groups_call[0][1]['json']

    assert len(groups_call) == 1
    assert len(users_call) == 0
    assert len(invite_call) == 1
    assert len(topic_call) == 1
    assert len(chat_call) == 1

    assert success_results[0] == 'Investigation mirrored successfully, channel: coolname'
    assert message_args['channel'] == 'new_group'
    assert message_args['text'] == 'This channel was created to mirror incident 999.' \
                                   ' \n View it on: https://www.eizelulz.com:8443#/WarRoom/999'

    assert group_args['is_private']
    assert len(our_conversation_filter) == 1
    assert len(our_mirror_filter) == 1
    assert our_conversation == {'id': 'new_group', 'name': 'coolname'}
    assert our_mirror == new_mirror


def test_mirror_investigation_new_mirror_with_topic(mocker):
    from SlackV3 import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        if method == 'conversations.create':
            if 'is_private' not in json:
                return {'channel': {
                    'id': 'new_channel', 'name': 'coolname'
                }}
            return {'channel': {
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
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

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

    success_results = demisto.results.call_args_list[0][0]
    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    new_conversations = js.loads(new_context['conversations'])
    our_conversation_filter = list(filter(lambda c: c['id'] == 'new_group', new_conversations))
    our_conversation = our_conversation_filter[0]
    our_mirror_filter = list(filter(lambda m: m['investigation_id'] == '999', new_mirrors))
    our_mirror = our_mirror_filter[0]

    calls = slack_sdk.WebClient.api_call.call_args_list
    groups_call = [c for c in calls if c[0][0] == 'conversations.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']
    chat_call = [c for c in calls if c[0][0] == 'chat.postMessage']

    message_args = chat_call[0][1]['json']
    topic_args = topic_call[0][1]['json']

    # Assert

    assert len(groups_call) == 1
    assert len(users_call) == 0
    assert len(invite_call) == 1
    assert len(topic_call) == 1
    assert len(chat_call) == 1

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
    from SlackV3 import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        return None

    mocker.patch.object(demisto, 'args', return_value={'type': 'chat', 'autoclose': 'false',
                                                       'direction': 'FromDemisto', 'mirrorTo': 'channel'})
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681', 'users': ['spengler']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

    # Arrange
    with pytest.raises(InterruptedError):
        mirror_investigation()

    err_msg = return_error_mock.call_args[0][0]

    calls = slack_sdk.WebClient.api_call.call_args_list
    channels_call = [c for c in calls if c[0][0] == 'conversations.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']

    # Assert
    assert len(topic_call) == 0
    assert len(users_call) == 0
    assert len(invite_call) == 0
    assert len(channels_call) == 0

    assert return_error_mock.call_count == 1
    assert err_msg == 'Cannot change the Slack channel type from XSOAR.'


def test_mirror_investigation_existing_mirror_error_name(mocker):
    from SlackV3 import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        return None

    mocker.patch.object(demisto, 'args', return_value={'channelName': 'eyy'})
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681', 'users': ['spengler']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

    # Arrange

    with pytest.raises(InterruptedError):
        mirror_investigation()

    err_msg = return_error_mock.call_args[0][0]

    calls = slack_sdk.WebClient.api_call.call_args_list
    channels_call = [c for c in calls if c[0][0] == 'conversations.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']

    # Assert
    assert len(invite_call) == 0
    assert len(channels_call) == 0
    assert len(users_call) == 0

    assert return_error_mock.call_count == 1
    assert err_msg == 'Cannot change the Slack channel name.'


def test_mirror_investigation_existing_investigation(mocker):
    from SlackV3 import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        return None

    mocker.patch.object(demisto, 'args', return_value={'type': 'chat', 'autoclose': 'false',
                                                       'direction': 'FromDemisto', 'mirrorTo': 'group'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681', 'users': ['spengler']})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

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

    calls = slack_sdk.WebClient.api_call.call_args_list
    channels_call = [c for c in calls if c[0][0] == 'conversations.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']

    # Assert
    assert len(channels_call) == 0
    assert len(users_call) == 0
    assert len(invite_call) == 0
    assert len(topic_call) == 0

    success_results = demisto.results.call_args_list[0][0]
    assert success_results[0] == 'Investigation mirrored successfully, channel: incident-681'

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: m['investigation_id'] == '681', new_mirrors))
    our_mirror = our_mirror_filter[0]

    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror


def test_mirror_investigation_existing_channel(mocker):
    from SlackV3 import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        return None

    mocker.patch.object(demisto, 'args', return_value={'channelName': 'group3', 'type': 'chat', 'autoclose': 'false',
                                                       'direction': 'FromDemisto', 'mirrorTo': 'group'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '999', 'users': ['spengler']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

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

    calls = slack_sdk.WebClient.api_call.call_args_list
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
    assert len(topic_call) == 1

    success_results = demisto.results.call_args_list[0][0]
    assert success_results[0] == 'Investigation mirrored successfully, channel: group3'

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: m['investigation_id'] == '999', new_mirrors))
    our_mirror = our_mirror_filter[0]

    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror


def test_mirror_investigation_existing_channel_remove_mirror(mocker):
    from SlackV3 import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        return None

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
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

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

    calls = slack_sdk.WebClient.api_call.call_args_list
    channels_call = [c for c in calls if c[0][0] == 'conversations.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']

    # Assert
    assert len(channels_call) == 0
    assert len(users_call) == 0
    assert len(invite_call) == 0
    assert len(topic_call) == 0

    success_results = demisto.results.call_args_list[0][0]
    assert success_results[0] == 'Investigation mirrored successfully, channel: group2'

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: m['investigation_id'] == '999', new_mirrors))
    our_mirror = our_mirror_filter[0]

    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror


def test_mirror_investigation_existing_channel_with_topic(mocker):
    from SlackV3 import mirror_investigation

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        return None

    mocker.patch.object(demisto, 'args', return_value={'channelName': 'group2', 'type': 'chat', 'autoclose': 'false',
                                                       'direction': 'FromDemisto', 'mirrorTo': 'group'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '999', 'users': ['spengler']})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

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

    calls = slack_sdk.WebClient.api_call.call_args_list
    channels_call = [c for c in calls if c[0][0] == 'conversations.create']
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']
    topic_call = [c for c in calls if c[0][0] == 'conversations.setTopic']

    # Assert
    assert len(channels_call) == 0
    assert len(users_call) == 0
    assert len(invite_call) == 0
    assert len(topic_call) == 0

    success_results = demisto.results.call_args_list[0][0]
    assert success_results[0] == 'Investigation mirrored successfully, channel: group2'

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: m['investigation_id'] == '999', new_mirrors))
    our_mirror = our_mirror_filter[0]

    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror


def test_check_for_mirrors(mocker):
    import SlackV3
    from SlackV3 import check_for_mirrors

    new_user = {
        'name': 'perikles',
        'profile': {
            'email': 'perikles@acropoli.com',
            'display_name': 'Dingus',
            'real_name': 'Lingus'
        },
        'id': 'U012B3CUI'
    }

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            users = {'members': js.loads(USERS)}
            users['members'].append(new_user)
            return users
        elif method == 'users.lookupByEmail':
            return {'user': new_user}
        return None

    # Set
    SlackV3.CACHE_EXPIRY = EXPIRED_TIMESTAMP
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

    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'mirrorInvestigation', return_value=[{'email': 'spengler@ghostbusters.example.com',
                                                                       'username': 'spengler'},
                                                                      {'email': 'perikles@acropoli.com',
                                                                       'username': 'perikles'}])

    # Arrange
    check_for_mirrors()

    calls = slack_sdk.WebClient.api_call.call_args_list
    users_call = [c for c in calls if c[0][0] == 'users.lookupByEmail']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']

    mirror_id = demisto.mirrorInvestigation.call_args[0][0]
    mirror_type = demisto.mirrorInvestigation.call_args[0][1]
    auto_close = demisto.mirrorInvestigation.call_args[0][2]

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    new_users = js.loads(new_context['users'])
    our_mirror_filter = list(filter(lambda m: m['investigation_id'] == '999', new_mirrors))
    our_mirror = our_mirror_filter[0]
    our_user_filter = list(filter(lambda u: u['id'] == 'U012B3CUI', new_users))
    our_user = our_user_filter[0]

    invited_users = [c[1]['json']['users'] for c in invite_call]
    channel = [c[1]['json']['channel'] for c in invite_call]

    # Assert
    assert len(users_call) == 1
    assert len(invite_call) == 2
    assert invited_users == ['U012A3CDE', 'U012B3CUI']
    assert channel == ['new_group', 'new_group']
    assert demisto.setIntegrationContext.call_count == 1
    assert len(our_mirror_filter) == 1
    assert our_mirror == new_mirror
    assert len(our_user_filter) == 1
    assert our_user == new_user

    assert mirror_id == '999'
    assert mirror_type == 'all:both'
    assert auto_close is True


def test_check_for_mirrors_no_updates(mocker):
    import SlackV3
    from SlackV3 import check_for_mirrors

    # Set
    SlackV3.CACHE_EXPIRY = EXPIRED_TIMESTAMP
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)

    # Arrange
    check_for_mirrors()

    # Assert
    assert demisto.getIntegrationContext.call_count == 1
    assert demisto.setIntegrationContext.call_count == 0


def test_check_for_mirrors_email_user_not_matching(mocker):
    import SlackV3
    from SlackV3 import check_for_mirrors

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        new_user = {
            'name': 'nope',
            'profile': {
                'email': 'perikles@acropoli.com',
            },
            'id': 'U012B3CUI'
        }
        if method == 'users.list':
            users = {'members': js.loads(USERS)}
            users['members'].append(new_user)
            return users
        elif method == 'users.lookupByEmail':
            return {'user': new_user}
        return None

    # Set
    SlackV3.CACHE_EXPIRY = EXPIRED_TIMESTAMP
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

    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'mirrorInvestigation', return_value=[{'email': 'spengler@ghostbusters.example.com',
                                                                       'username': 'spengler'},
                                                                      {'email': 'perikles@acropoli.com',
                                                                       'username': 'perikles'}])

    # Arrange
    check_for_mirrors()

    calls = slack_sdk.WebClient.api_call.call_args_list
    users_call = [c for c in calls if c[0][0] == 'users.lookupByEmail']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']

    invited_users = [c[1]['json']['users'] for c in invite_call]
    channel = [c[1]['json']['channel'] for c in invite_call]
    assert demisto.setIntegrationContext.call_count == 1

    # Assert
    assert len(users_call) == 1
    assert len(invite_call) == 2
    assert invited_users == ['U012A3CDE', 'U012B3CUI']
    assert channel == ['new_group', 'new_group']


def test_check_for_mirrors_email_not_matching(mocker):
    import SlackV3
    from SlackV3 import check_for_mirrors

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        users = {'members': js.loads(USERS)}
        new_user = {
            'name': 'perikles',
            'profile': {
                'email': 'bruce.wayne@pharmtech.zz',
            },
            'id': 'U012B3CUI'
        }

        users['members'].append(new_user)
        return users

    # Set
    SlackV3.CACHE_EXPIRY = EXPIRED_TIMESTAMP
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

    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'mirrorInvestigation', return_value=[{'email': 'spengler@ghostbusters.example.com',
                                                                       'username': 'spengler'},
                                                                      {'email': '',
                                                                       'username': 'perikles'}])

    # Arrange
    check_for_mirrors()

    calls = slack_sdk.WebClient.api_call.call_args_list
    users_call = [c for c in calls if c[0][0] == 'users.list']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']

    invited_users = [c[1]['json']['users'] for c in invite_call]
    channel = [c[1]['json']['channel'] for c in invite_call]

    # Assert
    assert len(users_call) == 1
    assert len(invite_call) == 2
    assert invited_users == ['U012A3CDE', 'U012B3CUI']
    assert channel == ['new_group', 'new_group']
    assert demisto.setIntegrationContext.call_count == 1


def test_check_for_mirrors_user_email_not_matching(mocker):
    import SlackV3
    from SlackV3 import check_for_mirrors

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        new_user = {
            'name': 'perikles',
            'profile': {
                'email': 'perikles@acropoli.com',
            },
            'id': 'U012B3CUI'
        }
        if method == 'users.list':
            users = {'members': js.loads(USERS)}
            users['members'].append(new_user)
            return users
        elif method == 'users.lookupByEmail':
            return {'user': {}}
        return None

    # Set
    SlackV3.CACHE_EXPIRY = EXPIRED_TIMESTAMP
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

    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'mirrorInvestigation', return_value=[{'email': 'spengler@ghostbusters.example.com',
                                                                       'username': 'spengler'},
                                                                      {'email': 'bruce.wayne@pharmtech.zz',
                                                                       'username': '123'}])
    mocker.patch.object(demisto, 'results')

    # Arrange
    check_for_mirrors()

    calls = slack_sdk.WebClient.api_call.call_args_list
    users_call = [c for c in calls if c[0][0] == 'users.lookupByEmail']
    invite_call = [c for c in calls if c[0][0] == 'conversations.invite']

    invited_users = [c[1]['json']['users'] for c in invite_call]
    channel = [c[1]['json']['channel'] for c in invite_call]

    error_results = demisto.results.call_args_list[0][0]

    # Assert
    assert demisto.setIntegrationContext.call_count == 1
    assert error_results[0]['Contents'] == 'User bruce.wayne@pharmtech.zz not found in Slack'
    assert len(users_call) == 1
    assert len(invite_call) == 1
    assert invited_users == ['U012A3CDE']
    assert channel == ['new_group']


@pytest.mark.asyncio
async def test_handle_dm_create_demisto_user(mocker):
    import SlackV3

    # Set
    async def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'conversations.open':
            return {
                'channel': {
                    'id': 'ey'
                }}
        else:
            return 'sup'

    async def fake_translate(message: str, user_name: str, user_email: str, demisto_user: dict):
        return "sup"

    socket_client = AsyncMock()

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'findUser', return_value={'id': 'demisto_id'})
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'translate_create', side_effect=fake_translate)
    mocker.patch.object(socket_client, 'api_call', side_effect=api_call)

    user = js.loads(USERS)[0]

    # Arrange
    await SlackV3.handle_dm(user, 'open 123 incident', socket_client)
    await SlackV3.handle_dm(user, 'new incident abu ahmad', socket_client)
    await SlackV3.handle_dm(user, 'incident create 817', socket_client)
    await SlackV3.handle_dm(user, 'incident open', socket_client)
    await SlackV3.handle_dm(user, 'incident new', socket_client)
    await SlackV3.handle_dm(user, 'create incident name=abc type=Access', socket_client)

    # Assert
    assert SlackV3.translate_create.call_count == 6

    incident_string = SlackV3.translate_create.call_args[0][0]
    user_name = SlackV3.translate_create.call_args[0][1]
    user_email = SlackV3.translate_create.call_args[0][2]
    demisto_user = SlackV3.translate_create.call_args[0][3]

    assert demisto_user == {'id': 'demisto_id'}
    assert user_name == 'spengler'
    assert user_email == 'spengler@ghostbusters.example.com'
    assert incident_string == 'create incident name=abc type=Access'


@pytest.mark.asyncio
async def test_handle_dm_nondemisto_user_shouldnt_create(mocker):
    import SlackV3

    # Set
    async def fake_translate(message: str, user_name: str, user_email: str, demisto_user: dict):
        return "sup"

    async def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'conversations.open':
            return {
                'channel': {
                    'id': 'ey'
                }}
        else:
            return 'sup'

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'findUser', return_value=None)
    mocker.patch.object(SlackV3, 'translate_create', side_effect=fake_translate)
    socket_client = AsyncMock()
    mocker.patch.object(socket_client, 'api_call', side_effect=api_call)
    user = js.loads(USERS)[0]

    # Arrange
    await SlackV3.handle_dm(user, 'create incident abc', socket_client)

    # Assert
    assert SlackV3.translate_create.call_count == 0


@pytest.mark.asyncio
async def test_handle_dm_nondemisto_user_should_create(mocker):
    import SlackV3

    mocker.patch.object(demisto, 'params', return_value={'allow_incidents': 'true'})

    SlackV3.init_globals()

    # Set
    async def fake_translate(message: str, user_name: str, user_email: str, demisto_user: dict):
        return "sup"

    async def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'conversations.open':
            return {
                'channel': {
                    'id': 'ey'
                }}
        else:
            return 'sup'

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'findUser', return_value=None)
    mocker.patch.object(SlackV3, 'translate_create', side_effect=fake_translate)
    socket_client = AsyncMock()
    mocker.patch.object(socket_client, 'api_call', side_effect=api_call)
    user = js.loads(USERS)[0]

    # Arrange
    await SlackV3.handle_dm(user, 'create incident abc', socket_client)

    # Assert
    assert SlackV3.translate_create.call_count == 1

    demisto_user = SlackV3.translate_create.call_args[0][3]
    assert demisto_user is None


@pytest.mark.asyncio
async def test_handle_dm_non_create_nonexisting_user(mocker):
    from SlackV3 import handle_dm

    # Set
    async def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'conversations.open':
            return {
                'channel': {
                    'id': 'ey'
                }}
        else:
            return 'sup'

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'findUser', return_value=None)
    mocker.patch.object(demisto, 'directMessage', return_value=None)
    socket_client = AsyncMock()
    mocker.patch.object(socket_client, 'api_call', side_effect=api_call)
    user = js.loads(USERS)[0]

    # Arrange
    await handle_dm(user, 'wazup', socket_client)

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
    from SlackV3 import handle_dm

    # Set
    async def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'conversations.open':
            return {
                'channel': {
                    'id': 'ey'
                }}
        elif method == 'chat.postMessage':
            text = json['text']
            if not text:
                raise InterruptedError
            return None
        else:
            return None

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'findUser', return_value=None)
    mocker.patch.object(demisto, 'directMessage', return_value=None)
    socket_client = AsyncMock()
    mocker.patch.object(socket_client, 'api_call', side_effect=api_call)
    user = js.loads(USERS)[0]

    # Arrange
    await handle_dm(user, 'wazup', socket_client)

    calls = socket_client.api_call.call_args_list
    chat_call = [c for c in calls if c[0][0] == 'chat.postMessage']
    message_args = chat_call[0][1]['json']

    # Assert
    assert message_args['text'] == 'Sorry, I could not perform the selected operation.'


@pytest.mark.asyncio
async def test_handle_dm_create_with_error(mocker):
    import SlackV3

    # Set
    async def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'conversations.open':
            return {
                'channel': {
                    'id': 'ey'
                }}
        else:
            return 'sup'

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'findUser', return_value={'id': 'demisto_id'})
    socket_client = AsyncMock()
    mocker.patch.object(socket_client, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'translate_create', side_effect=InterruptedError('omg'))

    user = js.loads(USERS)[0]

    # Arrange
    await SlackV3.handle_dm(user, 'open 123 incident', socket_client)

    # Assert
    assert SlackV3.translate_create.call_count == 1

    demisto_user = SlackV3.translate_create.call_args[0][3]
    incident_string = SlackV3.translate_create.call_args[0][0]
    calls = socket_client.api_call.call_args_list
    chat_call = [c for c in calls if c[0][0] == 'chat.postMessage']
    message_args = chat_call[0][1]['json']

    assert demisto_user == {'id': 'demisto_id'}
    assert incident_string == 'open 123 incident'
    assert message_args == {'channel': 'ey',
                            'text': 'Failed creating incidents: omg'}


@pytest.mark.asyncio
async def test_translate_create(mocker):
    import SlackV3

    # Set
    async def this_doesnt_create_incidents(incidents_json, user_name, email, demisto_id):
        return {
            'id': 'new_incident',
            'name': 'New Incident'
        }

    mocker.patch.object(SlackV3, 'create_incidents', side_effect=this_doesnt_create_incidents)
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
    json_data = await SlackV3.translate_create(json_message, 'spengler',
                                               'spengler@ghostbusters.example.com', demisto_user)
    wrong_json_data = await SlackV3.translate_create(wrong_json_message, 'spengler',
                                                     'spengler@ghostbusters.example.com', demisto_user)
    name_data = await SlackV3.translate_create(name_message, 'spengler',
                                               'spengler@ghostbusters.example.com', demisto_user)
    name_type_data = await SlackV3.translate_create(name_type_message, 'spengler',
                                                    'spengler@ghostbusters.example.com', demisto_user)
    type_name_data = await SlackV3.translate_create(type_name_message, 'spengler',
                                                    'spengler@ghostbusters.example.com', demisto_user)
    type_data = await SlackV3.translate_create(type_message, 'spengler',
                                               'spengler@ghostbusters.example.com', demisto_user)
    raw_json_prefix = '{"ReporterEmail": "spengler@ghostbusters.example.com", "Message": '
    expected_res = {"name": "xyz", "role": "Analyst",
                    "rawJSON": '{"ReporterEmail": "spengler@ghostbusters.example.com",'
                               ' "Message": "create incident json={\\u201cname\\u201d:'
                               ' \\u201cxyz\\u201d, \\u201crole\\u201d: \\u201cAnalyst\\u201d}"}'}
    create_args = SlackV3.create_incidents.call_args_list
    json_args = create_args[0][0][0]
    name_args = create_args[1][0][0]
    name_type_args = create_args[2][0][0]
    type_name_args = create_args[3][0][0]

    # Assert

    assert SlackV3.create_incidents.call_count == 4
    assert json_args[0] == expected_res
    assert name_args == [{'name': 'eyy', 'rawJSON': raw_json_prefix + '"create incident name=eyy"}'}]
    assert name_type_args == [{'name': 'eyy', 'type': 'Access',
                               'rawJSON': raw_json_prefix + '"create incident name= eyy type= Access"}'}]
    assert type_name_args == [{'name': 'eyy', 'type': 'Access',
                               'rawJSON': raw_json_prefix + '"create incident  type= Access name= eyy"}'}]

    assert json_data == success_message
    assert wrong_json_data == 'No other properties other than json should be specified.'
    assert name_data == success_message
    assert name_type_data == success_message
    assert type_name_data == success_message
    assert type_data == 'Please specify arguments in the following manner: name=<name> type=[type] or json=<json>.'


@pytest.mark.asyncio
async def test_translate_create_newline_json(mocker):
    # Set
    import SlackV3

    async def this_doesnt_create_incidents(incidents_json, user_name, email, demisto_id):
        return {
            'id': 'new_incident',
            'name': 'New Incident'
        }

    mocker.patch.object(SlackV3, 'create_incidents', side_effect=this_doesnt_create_incidents)
    mocker.patch.object(demisto, 'demistoUrls', return_value={'server': 'https://www.eizelulz.com:8443'})

    demisto_user = {'id': 'demisto_user'}

    json_message = \
        '''```
            create incident json={
            "name":"xyz",
            "details": "1.1.1.1,8.8.8.8"
            ```
        }'''

    success_message = 'Successfully created incident New Incident.\n' \
                      ' View it on: https://www.eizelulz.com:8443#/WarRoom/new_incident'

    # Arrange
    json_data = await SlackV3.translate_create(json_message, 'spengler', 'spengler@ghostbusters.example.com',
                                               demisto_user)

    create_args = SlackV3.create_incidents.call_args
    json_args = create_args[0][0]
    raw_json = '{"ReporterEmail": "spengler@ghostbusters.example.com", "Message":' \
               ' "            create incident json={            \\"name\\":\\"xyz\\",' \
               '            \\"details\\": \\"1.1.1.1,8.8.8.8\\"                    }"}'
    # Assert

    assert SlackV3.create_incidents.call_count == 1

    assert json_args == [{"name": "xyz", "details": "1.1.1.1,8.8.8.8", 'rawJSON': raw_json}]

    assert json_data == success_message


@pytest.mark.asyncio
async def test_create_incidents_no_labels(mocker):
    from SlackV3 import create_incidents

    # Set
    mocker.patch.object(demisto, 'createIncidents', return_value='nice')

    incidents = [{"name": "xyz", "details": "1.1.1.1,8.8.8.8"}]

    incidents_with_labels = [{'name': 'xyz', 'details': '1.1.1.1,8.8.8.8',
                              'labels': [{'type': 'Reporter', 'value': 'spengler'},
                                         {'type': 'ReporterEmail', 'value': 'spengler@ghostbusters.example.com'},
                                         {'type': 'Source', 'value': 'Slack'}]}]

    # Arrange
    data = await create_incidents(incidents, 'spengler', 'spengler@ghostbusters.example.com', 'demisto_user')

    incident_arg = demisto.createIncidents.call_args[0][0]
    user_arg = demisto.createIncidents.call_args[1]['userID']

    assert incident_arg == incidents_with_labels
    assert user_arg == 'demisto_user'
    assert data == 'nice'


@pytest.mark.asyncio
async def test_create_incidents_with_labels(mocker):
    from SlackV3 import create_incidents

    # Set
    mocker.patch.object(demisto, 'createIncidents', return_value='nice')

    incidents = [{'name': 'xyz', 'details': '1.1.1.1,8.8.8.8',
                  'labels': [{'type': 'Reporter', 'value': 'spengler'},
                             {'type': 'ReporterEmail', 'value': 'spengler@ghostbusters.example.com'}]}]

    incidents_with_labels = [{'name': 'xyz', 'details': '1.1.1.1,8.8.8.8',
                              'labels': [{'type': 'Reporter', 'value': 'spengler'},
                                         {'type': 'ReporterEmail', 'value': 'spengler@ghostbusters.example.com'},
                                         {'type': 'Source', 'value': 'Slack'}]}]

    # Arrange
    data = await create_incidents(incidents, 'spengler', 'spengler@ghostbusters.example.com', 'demisto_user')

    incident_arg = demisto.createIncidents.call_args[0][0]
    user_arg = demisto.createIncidents.call_args[1]['userID']

    assert incident_arg == incidents_with_labels
    assert user_arg == 'demisto_user'
    assert data == 'nice'


@pytest.mark.skip(reason="New version will always make the call")
@pytest.mark.asyncio
async def test_get_user_by_id_async_user_exists(mocker):
    import SlackV3
    from SlackV3 import get_user_by_id_async

    # Set
    async def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.info':
            return {'user': js.loads(USERS)[0]}
        return None

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    SlackV3.CACHE_EXPIRY = EXPIRED_TIMESTAMP

    user_id = 'U012A3CDE'

    # Arrange
    user = await get_user_by_id_async(slack_sdk.WebClient, user_id)

    # Assert
    assert slack_sdk.WebClient.api_call.call_count == 0
    assert demisto.setIntegrationContext.call_count == 0
    assert user['name'] == 'spengler'


@pytest.mark.skip(reason="New version will always make the call")
@pytest.mark.asyncio
async def test_get_user_by_id_async_user_doesnt_exist(mocker):
    import SlackV3
    from SlackV3 import get_user_by_id_async

    # Set
    async def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.info':
            return {'user': js.loads(USERS)[0]}
        return None

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext')
    socket_client = AsyncMock()
    mocker.patch.object(socket_client, 'api_call', side_effect=api_call)
    SlackV3.CACHE_EXPIRY = EXPIRED_TIMESTAMP

    user_id = 'XXXXXXX'

    # Arrange
    user = await get_user_by_id_async(socket_client, user_id)

    # Assert

    assert socket_client.api_call.call_count == 1
    assert demisto.setIntegrationContext.call_count == 1
    assert user['name'] == 'spengler'


@pytest.mark.asyncio
async def test_handle_text(mocker):
    import SlackV3

    # Set
    async def fake_clean(text, client):
        return 'מה הולך'

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'addEntry')
    mocker.patch.object(SlackV3, 'clean_message', side_effect=fake_clean)

    user = js.loads(USERS)[0]
    investigation_id = '999'
    text = 'מה הולך'

    # Arrange
    await SlackV3.handle_text(slack_sdk.WebClient, investigation_id, text, user)
    entry_args = demisto.addEntry.call_args[1]

    # Assert
    assert demisto.addEntry.call_count == 1
    assert entry_args['id'] == '999'
    assert entry_args['entry'] == 'מה הולך'
    assert entry_args['username'] == 'spengler'
    assert entry_args['email'] == 'spengler@ghostbusters.example.com'
    assert entry_args['footer'] == '\n**From Slack**'


@pytest.mark.skip(reason="New version means strings will always be handled by a different flow")
@pytest.mark.asyncio
async def test_check_entitlement(mocker):
    import SlackV3
    from SlackV3 import check_and_handle_entitlement

    # Set
    SlackV3.CACHE_EXPIRY = EXPIRED_TIMESTAMP
    mocker.patch.object(demisto, 'handleEntitlementForUser')

    user = {
        'id': 'U123456',
        'name': 'test',
        'profile': {
            'email': 'test@demisto.com'
        }
    }

    message1 = 'hi test'
    message2 = 'hi test@demisto.com 4404dae8-2d45-46bd-85fa-64779c12abe8@22 goodbye'
    message3 = 'hi test@demisto.com 4404dae8-2d45-46bd-85fa-64779c12abe8@e093ba05-3f3c-402e-81a7-149db969be5d|4 goodbye'
    message4 = 'hi test@demisto.com 4404dae8-2d45-46bd-85fa-64779c12abe8@22|43 goodbye'
    message5 = 'hi test@demisto.com 43434@e093ba05-3f3c-402e-81a7-149db969be5d goodbye'
    message6 = 'hi test@demisto.com name-of-someone@mail-of-someone goodbye'
    message7 = 'hi test@demisto.com 4404dae8-2d45-46bd-85fa-64779c12abe8@22_1|43 goodbye'
    message8 = 'hi test@demisto.com 4404dae8-2d45-46bd-85fa-64779c12abe8@22_2 goodbye'

    # Arrange
    result1 = await check_and_handle_entitlement(message1, user, '')
    result2 = await check_and_handle_entitlement(message2, user, '')
    result3 = await check_and_handle_entitlement(message3, user, '')
    result4 = await check_and_handle_entitlement(message4, user, '')
    result5 = await check_and_handle_entitlement(message5, user, '')
    result6 = await check_and_handle_entitlement(message6, user, '')
    result7 = await check_and_handle_entitlement(message7, user, '')
    result8 = await check_and_handle_entitlement(message8, user, '')

    result1_args = demisto.handleEntitlementForUser.call_args_list[0][0]
    result2_args = demisto.handleEntitlementForUser.call_args_list[1][0]
    result3_args = demisto.handleEntitlementForUser.call_args_list[2][0]
    result4_args = demisto.handleEntitlementForUser.call_args_list[3][0]
    result7_args = demisto.handleEntitlementForUser.call_args_list[4][0]
    result8_args = demisto.handleEntitlementForUser.call_args_list[5][0]

    assert result1 == 'Thank you for your response.'
    assert result2 == 'Thank you for your response.'
    assert result3 == 'Thank you for your response.'
    assert result4 == 'Thank you for your response.'
    assert result5 == ''
    assert result6 == ''
    assert result7 == 'Thank you for your response.'
    assert result8 == 'Thank you for your response.'

    assert demisto.handleEntitlementForUser.call_count == 6

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

    assert result7_args[0] == '22_1'
    assert result7_args[1] == '4404dae8-2d45-46bd-85fa-64779c12abe8'
    assert result7_args[2] == 'test@demisto.com'
    assert result7_args[3] == 'hi test@demisto.com  goodbye'
    assert result7_args[4] == '43'

    assert result8_args[0] == '22_2'
    assert result8_args[1] == '4404dae8-2d45-46bd-85fa-64779c12abe8'
    assert result8_args[2] == 'test@demisto.com'
    assert result8_args[3] == 'hi test@demisto.com  goodbye'
    assert result8_args[4] == ''


@pytest.mark.asyncio
async def test_check_entitlement_with_context(mocker):
    import SlackV3
    from SlackV3 import check_and_handle_entitlement

    # Set
    SlackV3.CACHE_EXPIRY = EXPIRED_TIMESTAMP
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
    import SlackV3

    # Set
    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_file', return_value='neat')
    mocker.patch.object(SlackV3, 'send_message', return_value='cool')

    # Arrange

    user_res = SlackV3.slack_send_request('spengler', None, None, message='Hi')
    channel_res = SlackV3.slack_send_request(None, 'general', None, file_dict='file')

    user_args = SlackV3.send_message.call_args[0]
    channel_args = SlackV3.send_file.call_args[0]

    calls = slack_sdk.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert SlackV3.send_message.call_count == 1
    assert SlackV3.send_file.call_count == 1

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


def test_reset_user_session(mocker):
    import SlackV3

    # Set
    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'admin.users.session.reset':
            return {'ok': True}
        return None

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(demisto, 'args', return_value={'user_id': 'U012A3CDE'})

    SlackV3.user_session_reset()


def test_send_request_channel_id(mocker):
    """
    Given:
        Test Case 1: A valid Channel ID as a destination to send a message to.
        Test Case 2: A valid Channel ID as a destination to send a file to.
    When:
        Test Case 1: Sending a message using a channel_id
        Test Case 2: Sending a file using a channel_id
    Then:
        Test Case 1: Assert that the endpoint was called using only the channel_id, and no other calls were made.
        Test Case 2: Assert that the endpoint was called using only the channel_id, and no other calls were made.
    """
    import SlackV3

    # Set
    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_file', return_value='neat')
    mocker.patch.object(SlackV3, 'send_message', return_value='cool')

    # Arrange

    channel_id_text_res = SlackV3.slack_send_request(to=None, channel=None, group=None, message='Hi', channel_id='C12345')
    channel_id_file_res = SlackV3.slack_send_request(to=None, channel=None, group=None, channel_id='C12345',
                                                     file_dict={'foo': 'file'})

    channel_id_text_args = SlackV3.send_message.call_args[0]
    channel_id_file_args = SlackV3.send_file.call_args[0]

    calls = slack_sdk.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert
    # Assert that NO user or channel APIs were called.
    assert len(users_call) == 0
    assert len(conversations_call) == 0

    assert SlackV3.send_message.call_count == 1
    assert SlackV3.send_file.call_count == 1

    assert channel_id_text_args[0] == ['C12345']
    assert channel_id_text_args[1] == ''
    assert channel_id_text_args[2] is False
    assert channel_id_text_args[4] == 'Hi'
    assert channel_id_text_args[5] == ''

    assert channel_id_file_args[0] == ['C12345']
    assert channel_id_file_args[1] == {'foo': 'file'}
    assert channel_id_file_args[3] == ''

    assert channel_id_text_res == 'cool'
    assert channel_id_file_res == 'neat'


def test_send_request_caching_disabled(mocker, capfd):
    import SlackV3

    # Set
    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_file', return_value='neat')
    mocker.patch.object(SlackV3, 'send_message', return_value='cool')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())

    SlackV3.DISABLE_CACHING = True
    # Arrange

    channel_id_text_res = SlackV3.slack_send_request(to=None, channel=None, group=None, message='Hi',
                                                     channel_id='C12345')
    channel_id_file_res = SlackV3.slack_send_request(to=None, channel=None, group=None, channel_id='C12345',
                                                     file_dict={'foo': 'file'})
    with capfd.disabled(), pytest.raises(InterruptedError):
        SlackV3.slack_send_request(to=None, channel='should-fail', group=None, message='Hi',
                                   channel_id=None)
    err_msg_1 = return_error_mock.call_args[0][0]

    assert err_msg_1 == "Could not find the Slack conversation should-fail. If caching is disabled, try searching by" \
                        " channel_id"

    with capfd.disabled(), pytest.raises(InterruptedError):
        SlackV3.slack_send_request(to=None, channel='should-fail', group=None, channel_id=None,
                                   file_dict={'foo': 'file'})
    err_msg_2 = return_error_mock.call_args[0][0]

    assert err_msg_2 == "Could not find the Slack conversation should-fail. If caching is disabled, try searching by" \
                        " channel_id"

    channel_id_text_args = SlackV3.send_message.call_args[0]
    channel_id_file_args = SlackV3.send_file.call_args[0]

    calls = slack_sdk.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert
    # Assert that NO user or channel APIs were called.
    assert len(users_call) == 0
    assert len(conversations_call) == 0

    assert SlackV3.send_message.call_count == 1
    assert SlackV3.send_file.call_count == 1

    assert channel_id_text_args[0] == ['C12345']
    assert channel_id_text_args[1] == ''
    assert channel_id_text_args[2] is False
    assert channel_id_text_args[4] == 'Hi'
    assert channel_id_text_args[5] == ''

    assert channel_id_file_args[0] == ['C12345']
    assert channel_id_file_args[1] == {'foo': 'file'}
    assert channel_id_file_args[3] == ''

    assert channel_id_text_res == 'cool'
    assert channel_id_file_res == 'neat'


def test_send_request_different_name(mocker):
    import SlackV3

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_message', return_value='cool')

    # Arrange
    channel_res = SlackV3.slack_send_request(None, 'incident-684', None, message='Hi')

    channel_args = SlackV3.send_message.call_args[0]

    calls = slack_sdk.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert SlackV3.send_message.call_count == 1

    assert channel_args[0] == ['GKB19PA3V']
    assert channel_args[1] == ''
    assert channel_args[2] is False
    assert channel_args[4] == 'Hi'
    assert channel_args[5] == ''

    assert channel_res == 'cool'


def test_send_request_with_severity(mocker):
    import SlackV3

    mocker.patch.object(demisto, 'params', return_value={'incidentNotificationChannel': 'general',
                                                         'min_severity': 'High',
                                                         'permitted_notifications': ['incidentOpened']})

    SlackV3.init_globals()

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={'severity': '3', 'message': '!!!',
                                                       'messageType': 'incidentOpened'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_message', return_value=SLACK_RESPONSE)

    # Arrange
    SlackV3.DISABLE_CACHING = False
    SlackV3.slack_send()

    send_args = SlackV3.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]

    calls = slack_sdk.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']
    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert SlackV3.send_message.call_count == 1

    assert send_args[0] == ['C012AB3CD']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == '!!!'
    assert send_args[5] == ''

    assert results[0]['HumanReadable'] == 'Message sent to Slack successfully.\nThread ID is: cool'


def test_send_request_with_notification_channel(mocker):
    import SlackV3

    mocker.patch.object(demisto, 'params', return_value={'incidentNotificationChannel': 'general',
                                                         'min_severity': 'High', 'notify_incidents': True,
                                                         'permitted_notifications': ['incidentOpened']})

    SlackV3.init_globals()

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={'channel': 'incidentNotificationChannel',
                                                       'severity': '4', 'message': '!!!',
                                                       'messageType': 'incidentOpened'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_message', return_value=SLACK_RESPONSE)

    # Arrange
    SlackV3.DISABLE_CACHING = False
    SlackV3.slack_send()

    send_args = SlackV3.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]

    calls = slack_sdk.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert SlackV3.send_message.call_count == 1

    assert send_args[0] == ['C012AB3CD']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == '!!!'
    assert send_args[5] == ''

    assert results[0]['HumanReadable'] == 'Message sent to Slack successfully.\nThread ID is: cool'


@pytest.mark.parametrize('notify', [False, True])
def test_send_request_with_notification_channel_as_dest(mocker, notify):
    import SlackV3

    mocker.patch.object(demisto, 'params', return_value={'incidentNotificationChannel': 'general',
                                                         'min_severity': 'High', 'notify_incidents': notify})

    SlackV3.init_globals()

    # Set
    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={'channel': 'general', 'message': '!!!'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_message', return_value=SLACK_RESPONSE)

    # Arrange
    SlackV3.DISABLE_CACHING = False
    SlackV3.slack_send()

    send_args = SlackV3.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]

    calls = slack_sdk.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert SlackV3.send_message.call_count == 1

    assert send_args[0] == ['C012AB3CD']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == '!!!'
    assert send_args[5] == ''

    assert results[0]['HumanReadable'] == 'Message sent to Slack successfully.\nThread ID is: cool'


def test_send_request_with_entitlement(mocker):
    import SlackV3

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
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
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_message', return_value=SLACK_RESPONSE)
    mocker.patch.object(SlackV3, 'get_current_utc_time', return_value=datetime(2019, 9, 26, 18, 38, 25))
    questions = [{
        'thread': 'cool',
        'entitlement': '4404dae8-2d45-46bd-85fa-64779c12abe8@22|43',
        'reply': 'Thanks bro',
        'expiry': '2019-09-26 18:38:25',
        'sent': '2019-09-26 18:38:25',
        'default_response': 'NoResponse'
    }]

    # Arrange
    SlackV3.slack_send()

    send_args = SlackV3.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]

    calls = slack_sdk.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert SlackV3.send_message.call_count == 1

    assert send_args[0] == ['im_channel']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == 'hi test@demisto.com'
    assert send_args[5] == ''

    assert results[0]['HumanReadable'] == 'Message sent to Slack successfully.\nThread ID is: cool'

    assert demisto.getIntegrationContext()['questions'] == js.dumps(questions)


def test_slack_send_with_mirrored_file(mocker):
    """
    Given:
      - mirror entry which is basically a file
    When:
      - running send-notification triggered from mirroring
    Then:
      - Validate that the file is sent successfully
    """
    import SlackV3

    mocker.patch.object(demisto, 'params', return_value={'enable_outbound_file_mirroring': True})

    SlackV3.init_globals()

    mocker.patch.object(
        demisto,
        'args',
        return_value={
            "message": "test",
            "channel_id": "1234",
            "channel": "channel",
            "entry": "1234",
            "messageType": SlackV3.MIRROR_TYPE,
            "entryObject": {}
        }
    )
    slack_send_request = mocker.patch.object(SlackV3, 'slack_send_request', return_value='file-sent')
    demisto_results = mocker.patch.object(demisto, 'results')

    SlackV3.slack_send()
    assert slack_send_request.call_args_list[0].kwargs["file_dict"]
    assert slack_send_request.call_args_list[0].kwargs["channel_id"] == "1234"
    assert demisto_results.call_args[0][0]['HumanReadable'] == 'File sent to Slack successfully.'


def test_send_request_with_entitlement_blocks(mocker):
    import SlackV3

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
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
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_message', return_value=SLACK_RESPONSE)
    mocker.patch.object(SlackV3, 'get_current_utc_time', return_value=datetime(2019, 9, 26, 18, 38, 25))
    questions = [{
        'thread': 'cool',
        'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
        'reply': 'Thanks bro',
        'expiry': '2019-09-26 18:38:25',
        'sent': '2019-09-26 18:38:25',
        'default_response': 'NoResponse'
    }]

    # Arrange
    SlackV3.slack_send()

    send_args = SlackV3.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]

    calls = slack_sdk.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert SlackV3.send_message.call_count == 1

    assert send_args[0] == ['im_channel']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == ''
    assert send_args[6] == js.dumps(BLOCK_JSON)

    assert results[0]['HumanReadable'] == 'Message sent to Slack successfully.\nThread ID is: cool'

    assert demisto.getIntegrationContext()['questions'] == js.dumps(questions)


def test_send_request_with_entitlement_blocks_message(mocker):
    import SlackV3

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
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
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_message', return_value=SLACK_RESPONSE)
    mocker.patch.object(SlackV3, 'get_current_utc_time', return_value=datetime(2019, 9, 26, 18, 38, 25))

    questions = [{
        'thread': 'cool',
        'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
        'reply': 'Thanks bro',
        'expiry': '2019-09-26 18:38:25',
        'sent': '2019-09-26 18:38:25',
        'default_response': 'NoResponse'
    }]

    # Arrange
    SlackV3.slack_send()

    send_args = SlackV3.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]

    calls = slack_sdk.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert SlackV3.send_message.call_count == 1

    assert send_args[0] == ['im_channel']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == 'wat up'
    assert send_args[6] == js.dumps(BLOCK_JSON)

    assert results[0]['HumanReadable'] == 'Message sent to Slack successfully.\nThread ID is: cool'

    assert demisto.getIntegrationContext()['questions'] == js.dumps(questions)


def test_send_to_user_lowercase(mocker):
    import SlackV3

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'args', return_value={'to': 'glenda@south.oz.coven', 'message': 'hi'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_file', return_value='neat')
    mocker.patch.object(SlackV3, 'send_message', return_value=SLACK_RESPONSE)

    # Arrange

    SlackV3.slack_send()

    send_args = SlackV3.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]

    calls = slack_sdk.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 0
    assert len(conversations_call) == 0
    assert SlackV3.send_message.call_count == 1

    assert send_args[0] == ['im_channel']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == 'hi'
    assert send_args[5] == ''

    assert results[0]['HumanReadable'] == 'Message sent to Slack successfully.\nThread ID is: cool'


def test_send_request_with_severity_user_doesnt_exist(mocker, capfd):
    import SlackV3

    mocker.patch.object(demisto, 'params', return_value={'incidentNotificationChannel': 'general',
                                                         'min_severity': 'High', 'notify_incidents': True,
                                                         'permitted_notifications': ['incidentOpened']})

    SlackV3.init_globals()
    SlackV3.DISABLE_CACHING = False
    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={'severity': '3', 'message': '!!!',
                                                       'messageType': 'incidentOpened', 'to': 'alexios'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_message', return_value=SLACK_RESPONSE)

    # Arrange
    with capfd.disabled():
        SlackV3.slack_send()

    send_args = SlackV3.send_message.call_args[0]

    results = demisto.results.call_args_list[0][0]
    calls = slack_sdk.WebClient.api_call.call_args_list

    users_call = [c for c in calls if c[0][0] == 'users.list']
    conversations_call = [c for c in calls if c[0][0] == 'conversations.list']

    # Assert

    assert len(users_call) == 1
    assert len(conversations_call) == 0
    assert SlackV3.send_message.call_count == 1

    assert send_args[0] == ['C012AB3CD']
    assert send_args[1] is None
    assert send_args[2] is False
    assert send_args[4] == '!!!'
    assert send_args[5] == ''

    assert results[0]['HumanReadable'] == 'Message sent to Slack successfully.\nThread ID is: cool'


def test_send_request_no_user(mocker, capfd):
    import SlackV3

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_file', return_value='neat')
    mocker.patch.object(SlackV3, 'send_message', return_value=SLACK_RESPONSE)

    # Arrange

    with capfd.disabled(), pytest.raises(InterruptedError):
        SlackV3.slack_send_request('alexios', None, None, message='Hi')
    err_msg = return_error_mock.call_args[0][0]

    calls = slack_sdk.WebClient.api_call.call_args_list
    users_call = [c for c in calls if c[0][0] == 'users.list']

    # Assert

    assert return_error_mock.call_count == 1
    assert err_msg == 'Could not find any destination to send to.'
    assert len(users_call) == 1
    assert SlackV3.send_message.call_count == 0
    assert SlackV3.send_file.call_count == 0


def test_send_request_no_severity(mocker):
    import SlackV3

    mocker.patch.object(demisto, 'params', return_value={'incidentNotificationChannel': 'general',
                                                         'min_severity': 'High', 'notify_incidents': True,
                                                         'permitted_notifications': ['incidentOpened']})

    SlackV3.init_globals()

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={'severity': '2', 'message': '!!!',
                                                       'messageType': 'incidentOpened'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_message', return_value=SLACK_RESPONSE)

    # Arrange
    with pytest.raises(InterruptedError):
        SlackV3.slack_send()

    err_msg = return_error_mock.call_args[0][0]

    calls = slack_sdk.WebClient.api_call.call_args_list
    users_call = [c for c in calls if c[0][0] == 'users.list']

    # Assert

    assert return_error_mock.call_count == 1
    assert err_msg == 'Either a user, group, channel id, or channel must be provided.'
    assert len(users_call) == 0
    assert SlackV3.send_message.call_count == 0


def test_send_request_zero_severity(mocker):
    import SlackV3

    mocker.patch.object(demisto, 'params', return_value={'incidentNotificationChannel': 'general',
                                                         'min_severity': 'High', 'notify_incidents': True,
                                                         'permitted_notifications': ['incidentOpened']})

    SlackV3.init_globals()

    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        elif method == 'conversations.list':
            return {'channels': js.loads(CONVERSATIONS)}
        elif method == 'conversations.open':
            return {'channel': {'id': 'im_channel'}}
        return {}

    mocker.patch.object(demisto, 'args', return_value={'severity': '0', 'message': '!!!',
                                                       'messageType': 'incidentOpened'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    mocker.patch.object(SlackV3, 'send_message', return_value=SLACK_RESPONSE)

    # Arrange
    with pytest.raises(InterruptedError):
        SlackV3.slack_send()

    err_msg = return_error_mock.call_args[0][0]

    calls = slack_sdk.WebClient.api_call.call_args_list
    users_call = [c for c in calls if c[0][0] == 'users.list']

    # Assert

    assert return_error_mock.call_count == 1
    assert err_msg == 'Either a user, group, channel id, or channel must be provided.'
    assert len(users_call) == 0
    assert SlackV3.send_message.call_count == 0


def test_send_message(mocker):
    import SlackV3
    # Set

    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(SlackV3, 'send_message_to_destinations')
    mocker.patch.object(SlackV3, 'invite_users_to_conversation')

    # Arrange
    SlackV3.send_message(['channel'], None, None, demisto.getIntegrationContext(), 'yo', None, '')

    args = SlackV3.send_message_to_destinations.call_args[0]

    # Assert
    assert SlackV3.send_message_to_destinations.call_count == 1

    assert args[0] == ['channel']
    assert args[1] == 'yo' + '\nView it on: ' + link
    assert args[2] is None


def test_send_message_to_destinations(mocker):
    import SlackV3
    # Set

    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(SlackV3, 'send_slack_request_sync')

    # Arrange
    SlackV3.send_message_to_destinations(['channel'], 'yo', None, '')

    args = SlackV3.send_slack_request_sync.call_args[1]

    # Assert
    assert SlackV3.send_slack_request_sync.call_count == 1
    assert 'http_verb' not in args
    assert args['body']['channel'] == 'channel'
    assert args['body']['text']


def test_send_file_to_destinations_request_args(mocker):
    """
    This mocks SlackV3.send_slack_request_sync while the other test mocks slack_sdk.WebClient.files_upload_v2
    Given:
        - A file to send to a specific Slack channel
    When:
        - Calling the send_slack_request_sync function
    Then:
        - Assert the function is called once and the correct arguments are sent to the function
    """
    import SlackV3
    # Set
    mocker.patch.object(SlackV3, 'send_slack_request_sync')

    # Arrange
    SlackV3.send_file_to_destinations(['channel'], {'name': 'name', 'path': 'yo'}, None)
    request_args = SlackV3.send_slack_request_sync.call_args[1]

    # Assert
    assert SlackV3.send_slack_request_sync.call_count == 1
    assert 'http_verb' not in request_args
    assert request_args['file_upload_params']['file'] == 'yo'
    assert request_args['file_upload_params']['filename'] == 'name'


def test_send_file_to_destinations_sdk_client_args(mocker):
    """
    This mocks slack_sdk.WebClient.files_upload_v2 while the other test mocks SlackV3.send_slack_request_sync
    Given:
        - A file to send to a specifc thread in a channel
    When:
        - Calling the files_upload_v2 'wrapper' method in the slack_sdk.WebClient class
    Then:
        - Assert correct arguments are sent to the method
    """
    from SlackV3 import send_file_to_destinations
    # Set
    mocker.patch.object(slack_sdk.WebClient, 'files_upload_v2')

    # Arrange
    send_file_to_destinations(['channel'], {'name': 'name', 'path': 'yo'}, 'thread')
    sdk_args = slack_sdk.WebClient.files_upload_v2.call_args[1]

    # Assert
    assert sdk_args['file'] == 'yo'
    assert sdk_args['filename'] == 'name'
    assert sdk_args['initial_comment'] is None
    assert sdk_args['channel'] == 'channel'
    assert sdk_args['thread_ts'] == 'thread'


def test_send_message_retry(mocker):
    import SlackV3
    from slack_sdk.errors import SlackApiError
    # Set

    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(SlackV3, 'invite_users_to_conversation')

    # Arrange
    mocker.patch.object(SlackV3, 'send_message_to_destinations',
                        side_effect=[SlackApiError('not_in_channel', None), 'ok'])
    SlackV3.send_message(['channel'], None, None, demisto.getIntegrationContext(), 'yo', None, '')

    args = SlackV3.send_message_to_destinations.call_args_list[1][0]

    # Assert
    assert SlackV3.send_message_to_destinations.call_count == 2

    assert args[0] == ['channel']
    assert args[1] == 'yo' + '\nView it on: ' + link
    assert args[2] is None


def test_send_file_retry(mocker):
    import SlackV3
    from slack_sdk.errors import SlackApiError
    # Set

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(SlackV3, 'invite_users_to_conversation')

    # Arrange
    mocker.patch.object(SlackV3, 'send_file_to_destinations',
                        side_effect=[SlackApiError('not_in_channel', None), 'ok'])
    SlackV3.send_file(['channel'], 'file', demisto.getIntegrationContext(), None)

    args = SlackV3.send_file_to_destinations.call_args_list[1][0]

    # Assert
    assert SlackV3.send_file_to_destinations.call_count == 2

    assert args[0] == ['channel']
    assert args[1] == 'file'
    assert args[2] is None


def test_close_channel_with_name(mocker):
    import SlackV3

    # Set

    mocker.patch.object(demisto, 'args', return_value={'channel': 'general'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(SlackV3, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(SlackV3, 'find_mirror_by_investigation', return_value={})
    mocker.patch.object(slack_sdk.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')

    # Arrange
    SlackV3.close_channel()

    close_args = slack_sdk.WebClient.api_call.call_args
    success_results = demisto.results.call_args[0]

    # Assert
    assert SlackV3.get_conversation_by_name.call_count == 1
    assert slack_sdk.WebClient.api_call.call_count == 1
    assert success_results[0] == 'Channel successfully archived.'
    assert close_args[0][0] == 'conversations.archive'
    assert close_args[1]['json']['channel'] == 'C012AB3CD'


def test_close_channel_should_delete_mirror(mocker):
    from SlackV3 import close_channel
    # Set

    mirrors = js.loads(MIRRORS)
    mirrors.pop(0)

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'mirrorInvestigation')
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(slack_sdk.WebClient, 'api_call')

    # Arrange
    close_channel()

    archive_args = slack_sdk.WebClient.api_call.call_args
    context_args = demisto.setIntegrationContext.call_args[0][0]
    context_args_mirrors = js.loads(context_args['mirrors'])
    mirror_args = demisto.mirrorInvestigation.call_args[0]

    # Assert
    assert archive_args[0][0] == 'conversations.archive'
    assert archive_args[1]['json']['channel'] == 'GKQ86DVPH'
    assert context_args_mirrors == mirrors
    assert mirror_args == ('681', 'none:both', True)


def test_close_channel_should_delete_mirrors(mocker):
    from SlackV3 import close_channel
    # Set

    mirrors = js.loads(MIRRORS)
    mirrors.pop(1)
    mirrors.pop(1)

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'investigation', return_value={'id': '684'})
    mocker.patch.object(demisto, 'mirrorInvestigation')
    mocker.patch.object(slack_sdk.WebClient, 'api_call')

    # Arrange
    close_channel()

    archive_args = slack_sdk.WebClient.api_call.call_args
    context_args = demisto.setIntegrationContext.call_args[0][0]
    mirrors_args = [args[0] for args in demisto.mirrorInvestigation.call_args_list]
    context_args_mirrors = js.loads(context_args['mirrors'])

    # Assert
    assert archive_args[0][0] == 'conversations.archive'
    assert archive_args[1]['json']['channel'] == 'GKB19PA3V'
    assert context_args_mirrors == mirrors
    assert mirrors_args == [('684', 'none:both', True), ('692', 'none:both', True)]


def test_get_conversation_by_name_paging(mocker):
    from SlackV3 import get_conversation_by_name
    # Set

    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'conversations.list':
            if len(params) == 3:
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
        return None

    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

    # Arrange
    channel = get_conversation_by_name('lulz')
    args = slack_sdk.WebClient.api_call.call_args_list
    first_args = args[0][1]
    second_args = args[1][1]

    # Assert
    assert args[0][0][0] == 'conversations.list'
    assert len(first_args['params']) == 3
    assert first_args['params']['limit'] == 200
    assert len(second_args['params']) == 4
    assert second_args['params']['cursor'] == 'dGVhbTpDQ0M3UENUTks='
    assert channel['id'] == 'C248918AB'
    assert slack_sdk.WebClient.api_call.call_count == 2


def test_send_file_no_args_investigation(mocker):
    import SlackV3

    # Set

    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'getFilePath', return_value={'path': 'path', 'name': 'name'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(SlackV3, 'slack_send_request', return_value='cool')

    # Arrange
    SlackV3.slack_send_file()

    send_args = SlackV3.slack_send_request.call_args
    success_results = demisto.results.call_args[0]

    # Assert
    assert SlackV3.slack_send_request.call_count == 1
    assert success_results[0]['HumanReadable'] == 'File sent to Slack successfully.'

    assert send_args[0][1] == 'incident-681'
    assert send_args[1]['file_dict'] == {
        'path': 'path',
        'name': 'name',
        'comment': ''
    }


def test_send_file_no_args_no_investigation(mocker):
    import SlackV3

    # Set

    mocker.patch.object(demisto, 'args', return_value={})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '999'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(SlackV3, 'slack_send_request', return_value='cool')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())

    # Arrange
    with pytest.raises(InterruptedError):
        SlackV3.slack_send_file()

    err_msg = return_error_mock.call_args[0][0]

    # Assert
    assert SlackV3.slack_send_request.call_count == 0
    assert err_msg == 'Either a user, group, channel id or channel must be provided.'


def test_set_topic(mocker):
    import SlackV3

    # Set

    mocker.patch.object(demisto, 'args', return_value={'channel': 'general', 'topic': 'ey'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(SlackV3, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(slack_sdk.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')

    # Arrange
    SlackV3.set_channel_topic()

    send_args = slack_sdk.WebClient.api_call.call_args
    success_results = demisto.results.call_args[0]

    # Assert
    assert SlackV3.get_conversation_by_name.call_count == 1
    assert slack_sdk.WebClient.api_call.call_count == 1
    assert success_results[0] == 'Topic successfully set.'
    assert send_args[0][0] == 'conversations.setTopic'
    assert send_args[1]['json']['channel'] == 'C012AB3CD'
    assert send_args[1]['json']['topic'] == 'ey'


def test_set_topic_no_args_investigation(mocker):
    import SlackV3

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
    mocker.patch.object(SlackV3, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(slack_sdk.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')

    # Arrange
    SlackV3.set_channel_topic()

    send_args = slack_sdk.WebClient.api_call.call_args
    success_results = demisto.results.call_args[0]

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: m['investigation_id'] == '681', new_mirrors))
    our_mirror = our_mirror_filter[0]

    # Assert
    assert SlackV3.get_conversation_by_name.call_count == 0
    assert slack_sdk.WebClient.api_call.call_count == 1
    assert success_results[0] == 'Topic successfully set.'
    assert send_args[0][0] == 'conversations.setTopic'
    assert send_args[1]['json']['channel'] == 'GKQ86DVPH'
    assert send_args[1]['json']['topic'] == 'ey'
    assert new_mirror == our_mirror


def test_set_topic_no_args_no_investigation(mocker):
    import SlackV3

    # Set

    mocker.patch.object(demisto, 'args', return_value={'topic': 'ey'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '9999'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(SlackV3, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(slack_sdk.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())

    # Arrange
    with pytest.raises(InterruptedError):
        SlackV3.set_channel_topic()

    err_msg = return_error_mock.call_args[0][0]

    # Assert
    assert SlackV3.get_conversation_by_name.call_count == 0
    assert err_msg == 'The channel was not found. Either the Slack app is not a member of the channel, or the slack app ' \
                      'does not have permission to find the channel.'


def test_invite_users(mocker):
    import SlackV3

    # Set

    mocker.patch.object(demisto, 'args', return_value={'channel': 'general', 'users': 'spengler, glinda'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(SlackV3, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(SlackV3, 'invite_users_to_conversation')
    mocker.patch.object(demisto, 'results')

    # Arrange
    SlackV3.invite_to_channel()

    send_args = SlackV3.invite_users_to_conversation.call_args[0]
    success_results = demisto.results.call_args[0]

    # Assert
    assert SlackV3.get_conversation_by_name.call_count == 1
    assert SlackV3.invite_users_to_conversation.call_count == 1
    assert success_results[0] == 'Successfully invited users to the channel.'
    assert send_args[0] == 'C012AB3CD'
    assert send_args[1] == ['U012A3CDE', 'U07QCRPA4']


def test_invite_users_no_channel(mocker):
    import SlackV3

    # Set

    mocker.patch.object(demisto, 'args', return_value={'users': 'spengler, glinda'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(SlackV3, 'get_conversation_by_name', return_value={'id': 'GKQ86DVPH'})
    mocker.patch.object(SlackV3, 'invite_users_to_conversation')
    mocker.patch.object(demisto, 'results')

    # Arrange
    SlackV3.invite_to_channel()

    send_args = SlackV3.invite_users_to_conversation.call_args[0]
    success_results = demisto.results.call_args[0]

    # Assert
    assert SlackV3.get_conversation_by_name.call_count == 0
    assert SlackV3.invite_users_to_conversation.call_count == 1
    assert success_results[0] == 'Successfully invited users to the channel.'
    assert send_args[0] == 'GKQ86DVPH'
    assert send_args[1] == ['U012A3CDE', 'U07QCRPA4']


def test_invite_users_no_channel_doesnt_exist(mocker):
    import SlackV3

    # Set

    mocker.patch.object(demisto, 'args', return_value={'users': 'spengler, glinda'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '777'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(SlackV3, 'get_conversation_by_name', return_value={'id': 'GKQ86DVPH'})
    mocker.patch.object(SlackV3, 'invite_users_to_conversation')
    mocker.patch.object(demisto, 'results')

    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())

    # Arrange
    with pytest.raises(InterruptedError):
        SlackV3.invite_to_channel()

    err_msg = return_error_mock.call_args[0][0]

    # Assert
    assert SlackV3.get_conversation_by_name.call_count == 0
    assert SlackV3.invite_users_to_conversation.call_count == 0
    assert err_msg == 'The channel was not found. Either the Slack app is not a member of the channel, or the slack app ' \
                      'does not have permission to find the channel.'


def test_kick_users(mocker):
    import SlackV3

    # Set

    mocker.patch.object(demisto, 'args', return_value={'channel': 'general', 'users': 'spengler, glinda'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(SlackV3, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(SlackV3, 'kick_users_from_conversation')
    mocker.patch.object(demisto, 'results')

    # Arrange
    SlackV3.kick_from_channel()

    send_args = SlackV3.kick_users_from_conversation.call_args[0]
    success_results = demisto.results.call_args[0]

    # Assert
    assert SlackV3.get_conversation_by_name.call_count == 1
    assert SlackV3.kick_users_from_conversation.call_count == 1
    assert success_results[0] == 'Successfully kicked users from the channel.'
    assert send_args[0] == 'C012AB3CD'
    assert send_args[1] == ['U012A3CDE', 'U07QCRPA4']


def test_kick_users_no_channel(mocker):
    import SlackV3

    # Set

    mocker.patch.object(demisto, 'args', return_value={'users': 'spengler, glinda'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(SlackV3, 'get_conversation_by_name', return_value={'id': 'GKQ86DVPH'})
    mocker.patch.object(SlackV3, 'kick_users_from_conversation')
    mocker.patch.object(demisto, 'results')

    # Arrange
    SlackV3.DISABLE_CACHING = False
    SlackV3.kick_from_channel()

    send_args = SlackV3.kick_users_from_conversation.call_args[0]
    success_results = demisto.results.call_args[0]

    # Assert
    assert SlackV3.get_conversation_by_name.call_count == 0
    assert SlackV3.kick_users_from_conversation.call_count == 1
    assert success_results[0] == 'Successfully kicked users from the channel.'
    assert send_args[0] == 'GKQ86DVPH'
    assert send_args[1] == ['U012A3CDE', 'U07QCRPA4']


def test_kick_users_no_channel_doesnt_exist(mocker):
    import SlackV3

    # Set

    mocker.patch.object(demisto, 'args', return_value={'users': 'spengler, glinda'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '777'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(SlackV3, 'get_conversation_by_name', return_value={'id': 'GKQ86DVPH'})
    mocker.patch.object(SlackV3, 'invite_users_to_conversation')
    mocker.patch.object(demisto, 'results')

    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())

    # Arrange
    with pytest.raises(InterruptedError):
        SlackV3.kick_from_channel()

    err_msg = return_error_mock.call_args[0][0]

    # Assert
    assert SlackV3.get_conversation_by_name.call_count == 0
    assert SlackV3.invite_users_to_conversation.call_count == 0
    assert err_msg == 'The channel was not found. Either the Slack app is not a member of the channel, or the slack app ' \
                      'does not have permission to find the channel.'


def test_rename_channel(mocker):
    import SlackV3

    # Set

    mocker.patch.object(demisto, 'args', return_value={'channel': 'general', 'name': 'ey'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '681'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(SlackV3, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(slack_sdk.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')

    # Arrange
    SlackV3.rename_channel()

    send_args = slack_sdk.WebClient.api_call.call_args
    success_results = demisto.results.call_args[0]

    # Assert
    assert SlackV3.get_conversation_by_name.call_count == 1
    assert slack_sdk.WebClient.api_call.call_count == 1
    assert success_results[0] == 'Channel renamed successfully.'
    assert send_args[0][0] == 'conversations.rename'
    assert send_args[1]['json']['channel'] == 'C012AB3CD'
    assert send_args[1]['json']['name'] == 'ey'


def test_rename_no_args_investigation(mocker):
    import SlackV3

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
    mocker.patch.object(SlackV3, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(slack_sdk.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')

    # Arrange
    SlackV3.rename_channel()

    send_args = slack_sdk.WebClient.api_call.call_args
    success_results = demisto.results.call_args[0]

    new_context = demisto.setIntegrationContext.call_args[0][0]
    new_mirrors = js.loads(new_context['mirrors'])
    our_mirror_filter = list(filter(lambda m: m['investigation_id'] == '681', new_mirrors))
    our_mirror = our_mirror_filter[0]

    # Assert
    assert SlackV3.get_conversation_by_name.call_count == 0
    assert slack_sdk.WebClient.api_call.call_count == 1
    assert success_results[0] == 'Channel renamed successfully.'
    assert send_args[0][0] == 'conversations.rename'
    assert send_args[1]['json']['channel'] == 'GKQ86DVPH'
    assert send_args[1]['json']['name'] == 'ey'
    assert new_mirror == our_mirror


def test_rename_no_args_no_investigation(mocker):
    import SlackV3

    # Set

    mocker.patch.object(demisto, 'args', return_value={'name': 'ey'})
    mocker.patch.object(demisto, 'investigation', return_value={'id': '9999'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(SlackV3, 'get_conversation_by_name', return_value={'id': 'C012AB3CD'})
    mocker.patch.object(slack_sdk.WebClient, 'api_call')
    mocker.patch.object(demisto, 'results')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())

    # Arrange
    with pytest.raises(InterruptedError):
        SlackV3.rename_channel()

    err_msg = return_error_mock.call_args[0][0]

    # Assert
    assert SlackV3.get_conversation_by_name.call_count == 0
    assert err_msg == 'The channel was not found. Either the Slack app is not a member of the channel, or the slack app ' \
                      'does not have permission to find the channel.'


def test_get_user(mocker):
    from SlackV3 import get_user

    # Set
    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        new_user = {
            'name': 'perikles',
            'profile': {
                'email': 'perikles@acropoli.com',
                'display_name': 'Dingus',
                'real_name': 'Lingus'
            },
            'id': 'U012B3CUI'
        }
        if method == 'users.info':
            user = {'user': js.loads(USERS)[0]}
            return user
        elif method == 'users.lookupByEmail':
            return {'user': new_user}
        return None

    mocker.patch.object(demisto, 'args', return_value={'user': 'spengler'})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
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
    import SlackV3
    from slack_sdk.errors import SlackApiError
    from slack_sdk.web.slack_response import SlackResponse
    import time

    # Set
    SlackV3.init_globals()
    SlackV3.DISABLE_CACHING = False
    err_response: SlackResponse = SlackResponse(api_url='', client=None, http_verb='GET', req_args={},
                                                data={'ok': False}, status_code=429, headers={'Retry-After': 30})
    first_call = {'members': js.loads(USERS), 'response_metadata': {'next_cursor': 'dGVhbTpDQ0M3UENUTks='}}
    second_call = SlackApiError('Rate limit reached!', err_response)
    third_call = {'members': [{'id': 'U248918AB', 'name': 'alexios'}], 'response_metadata': {'next_cursor': ''}}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=[first_call, second_call, third_call])
    mocker.patch.object(time, 'sleep')

    # Arrange
    user = SlackV3.get_user_by_name('alexios')
    args = slack_sdk.WebClient.api_call.call_args_list
    first_args = args[0][1]
    second_args = args[2][1]

    # Assert
    assert len(first_args['params']) == 1
    assert first_args['params']['limit'] == 200
    assert len(second_args['params']) == 2
    assert second_args['params']['cursor'] == 'dGVhbTpDQ0M3UENUTks='
    assert user['id'] == 'U248918AB'
    assert slack_sdk.WebClient.api_call.call_count == 3


def test_get_user_by_name_paging_rate_limit_error(mocker):
    import SlackV3
    from slack_sdk.errors import SlackApiError
    from slack_sdk.web.slack_response import SlackResponse
    import time

    # Set
    SlackV3.init_globals()
    SlackV3.DISABLE_CACHING = False
    err_response: SlackResponse = SlackResponse(api_url='', client=None, http_verb='GET', req_args={},
                                                data={'ok': False}, status_code=429, headers={'Retry-After': 40})
    first_call = {'members': js.loads(USERS), 'response_metadata': {'next_cursor': 'dGVhbTpDQ0M3UENUTks='}}
    second_call = SlackApiError('Rate limit reached!', err_response)
    third_call = {'members': [{'id': 'U248918AB', 'name': 'alexios'}], 'response_metadata': {'next_cursor': ''}}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=[first_call, second_call, second_call, third_call])
    mocker.patch.object(time, 'sleep')

    # Arrange
    with pytest.raises(SlackApiError):
        SlackV3.get_user_by_name('alexios')
    args = slack_sdk.WebClient.api_call.call_args_list
    first_args = args[0][1]

    # Assert
    assert len(first_args['params']) == 1
    assert first_args['params']['limit'] == 200
    assert slack_sdk.WebClient.api_call.call_count == 3


def test_get_user_by_name_paging_normal_error(mocker):
    import SlackV3
    from slack_sdk.errors import SlackApiError
    from slack_sdk.web.slack_response import SlackResponse

    # Set
    SlackV3.init_globals()
    SlackV3.DISABLE_CACHING = False
    err_response: SlackResponse = SlackResponse(api_url='', client=None, http_verb='GET', req_args={},
                                                data={'ok': False}, status_code=500, headers={})
    first_call = {'members': js.loads(USERS), 'response_metadata': {'next_cursor': 'dGVhbTpDQ0M3UENUTks='}}
    second_call = SlackApiError('Whoops!', err_response)
    third_call = {'members': [{'id': 'U248918AB', 'name': 'alexios'}], 'response_metadata': {'next_cursor': ''}}

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=[first_call, second_call, third_call])

    # Arrange
    with pytest.raises(SlackApiError):
        SlackV3.get_user_by_name('alexios')
    args = slack_sdk.WebClient.api_call.call_args_list
    first_args = args[0][1]

    # Assert
    assert len(first_args['params']) == 1
    assert first_args['params']['limit'] == 200
    assert slack_sdk.WebClient.api_call.call_count == 2


def test_message_setting_name_and_icon(mocker):
    from SlackV3 import send_slack_request_sync, init_globals

    mocker.patch.object(demisto, 'params', return_value={'bot_name': 'kassandra', 'bot_icon': 'coolimage'})

    init_globals()

    # Set
    mocker.patch.object(slack_sdk.WebClient, 'api_call')

    # Arrange
    send_slack_request_sync(slack_sdk.WebClient, 'chat.postMessage', body={'channel': 'c', 'text': 't'})
    send_args = slack_sdk.WebClient.api_call.call_args[1]

    # Assert
    assert 'username' in send_args['json']
    assert 'icon_url' in send_args['json']


def test_message_not_setting_name_and_icon(mocker):
    from SlackV3 import send_slack_request_sync, init_globals

    mocker.patch.object(demisto, 'params', return_value={'bot_name': 'kassandra', 'bot_icon': 'coolimage'})

    init_globals()

    # Set
    mocker.patch.object(slack_sdk.WebClient, 'api_call')

    # Arrange
    send_slack_request_sync(slack_sdk.WebClient, 'conversations.setTopic', body={'channel': 'c', 'topic': 't'})
    send_args = slack_sdk.WebClient.api_call.call_args[1]

    # Assert
    assert 'username' not in send_args['json']
    assert 'icon_url' not in send_args['json']


@pytest.mark.asyncio
async def test_message_setting_name_and_icon_async(mocker):
    from SlackV3 import send_slack_request_async, init_globals

    # Set
    async def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        return

    mocker.patch.object(demisto, 'params', return_value={'bot_name': 'kassandra', 'bot_icon': 'coolimage'})

    init_globals()

    socket_client = AsyncMock()
    mocker.patch.object(socket_client.web_client, 'api_call', side_effect=api_call)

    # Arrange
    await send_slack_request_async(socket_client, 'chat.postMessage', body={'channel': 'c', 'text': 't'})
    send_args = socket_client.api_call.call_args[1]

    # Assert
    assert 'username' in send_args['json']
    assert 'icon_url' in send_args['json']


@pytest.mark.asyncio
async def test_message_not_setting_name_and_icon_async(mocker):
    from SlackV3 import send_slack_request_async, init_globals

    # Set
    async def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        return

    mocker.patch.object(demisto, 'params', return_value={'bot_name': 'kassandra', 'bot_icon': 'coolimage'})

    init_globals()

    socket_client = AsyncMock()
    mocker.patch.object(socket_client.web_client, 'api_call', side_effect=api_call)

    # Arrange
    await send_slack_request_async(socket_client, 'conversations.setTopic', body={'channel': 'c', 'topic': 't'})
    send_args = socket_client.api_call.call_args[1]

    # Assert
    assert 'username' not in send_args['json']
    assert 'icon_url' not in send_args['json']


def test_set_proxy_and_ssl(mocker):
    import SlackV3
    import ssl

    # Set
    mocker.patch.object(demisto, 'params', return_value={'unsecure': 'true', 'proxy': 'true'})
    mocker.patch.object(slack_sdk, 'WebClient')
    mocker.patch.object(SlackV3, 'handle_proxy', return_value={'https': 'https_proxy', 'http': 'http_proxy'})

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # Arrange
    SlackV3.init_globals()
    init_args = slack_sdk.WebClient.call_args[1]
    assert init_args['ssl'].check_hostname is False
    assert init_args['ssl'].verify_mode == ssl.CERT_NONE
    assert init_args['proxy'] == 'http_proxy'


def test_set_proxy_by_url(mocker):
    import SlackV3
    import ssl

    # Set
    mocker.patch.object(demisto, 'params', return_value={'unsecure': 'true', 'proxy': 'true'})
    mocker.patch.object(slack_sdk, 'WebClient')
    mocker.patch.object(SlackV3, 'handle_proxy', return_value={'https': 'https_proxy', 'http': 'http_proxy'})

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # Arrange
    SlackV3.init_globals()
    init_args = slack_sdk.WebClient.call_args[1]
    assert init_args['ssl'].check_hostname is False
    assert init_args['ssl'].verify_mode == ssl.CERT_NONE
    assert init_args['proxy'] == 'http_proxy'


def test_unset_proxy_and_ssl(mocker):
    from SlackV3 import init_globals

    # Set
    mocker.patch.object(slack_sdk, 'WebClient')

    # Arrange
    init_globals()
    init_args = slack_sdk.WebClient.call_args[1]
    assert init_args['ssl'] is None
    assert init_args['proxy'] is None


def test_fail_connect_threads(mocker):
    import SlackV3
    mocker.patch.object(demisto, 'params', return_value={'unsecure': 'true', 'bot_token': '123'})
    mocker.patch.object(demisto, 'args', return_value={'to': 'test', 'message': 'test message'})
    mocker.patch.object(demisto, 'error')
    mocker.patch.object(demisto, 'command', return_value='send-notification')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    for _i in range(8):
        SlackV3.main()
        time.sleep(0.5)
    assert return_error_mock.call_count == 8
    assert threading.active_count() < 6  # we shouldn't have more than 5 threads (1 + 4 max size of executor)


def test_slack_send_filter_one_mirror_tag(mocker):
    # When filtered_tags parameter contains the same tag as the entry tag - slack_send method should send the message
    import SlackV3

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(SlackV3, 'slack_send_request', return_value=SLACK_RESPONSE_2)

    mocker.patch.object(demisto, 'args', return_value={'to': 'demisto', 'messageType': 'mirrorEntry',
                                                       'entryObject': {'tags': ['tag1']}})

    mocker.patch.object(demisto, 'params', return_value={'filtered_tags': 'tag1'})
    SlackV3.slack_send()
    assert demisto.results.mock_calls[0][1][0]['HumanReadable'] == 'Message sent to Slack successfully.\nThread ID is: None'


def test_slack_send_filter_no_mirror_tags(mocker):
    # When filtered_tags parameter is empty slack_send method should send the message
    import SlackV3

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(SlackV3, 'slack_send_request', return_value=SLACK_RESPONSE_2)

    mocker.patch.object(demisto, 'args', return_value={'to': 'demisto', 'messageType': 'mirrorEntry',
                                                       'entryObject': {'tags': ['tag1']}})

    mocker.patch.object(demisto, 'params', return_value={'filtered_tags': ''})
    SlackV3.slack_send()
    assert demisto.results.mock_calls[0][1][0]['HumanReadable'] == 'Message sent to Slack successfully.\nThread ID is: None'


def test_slack_send_filter_no_entry_tags(mocker):
    # When filtered_tags parameter contains one tag to filter messages and the entry have no tags -
    # slack_send method should exit and demisto.results.mock_calls should be empty
    import SlackV3

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(SlackV3, 'slack_send_request', return_value={'cool': 'cool'})

    mocker.patch.object(demisto, 'args', return_value={'to': 'demisto', 'messageType': 'mirrorEntry',
                                                       'entryObject': {'tags': []}})

    mocker.patch.object(demisto, 'params', return_value={'filtered_tags': 'tag1'})
    SlackV3.slack_send()
    assert demisto.results.mock_calls == []


def test_handle_tags_in_message_sync(mocker):
    from SlackV3 import handle_tags_in_message_sync

    # Set
    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        return None

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

    user_exists_message = 'Hello <@spengler>!'
    user_exists_message_in_email = "Hello <@spengler>! connected with spengler@ghostbusters.example.com !"
    user_doesnt_exist_message = 'Goodbye <@PetahTikva>!'

    user_message_exists_result = handle_tags_in_message_sync(user_exists_message)
    user_message_exists_in_email_result = handle_tags_in_message_sync(user_exists_message_in_email)
    user_message_doesnt_exist_result = handle_tags_in_message_sync(user_doesnt_exist_message)

    # Assert

    assert user_message_exists_result == 'Hello <@U012A3CDE>!'
    assert user_message_exists_in_email_result == 'Hello <@U012A3CDE>! connected with spengler@ghostbusters.example.com !'
    assert user_message_doesnt_exist_result == 'Goodbye PetahTikva!'


def test_send_message_to_destinations_non_strict():
    """
    Given:
        Blocks with non-strict json

    When:
        Sending message

    Then:
        No error is raised
    """
    from SlackV3 import send_message_to_destinations
    blocks = """[
                  {
                      "type": "section",
                      "text": {
                          "type": "mrkdwn",
                          "text": "*<${incident.siemlink}|${incident.name}>*\n${incident.details}"
                      }
                  },
                  {
                      "type": "section",
                      "fields": [
                          {
                              "type": "mrkdwn",
                              "text": "*Account ID:*\n${incident.accountid} "
                          }
                      ]
                  },
                  {
                      "type": "actions",
                      "elements": [
                          {
                              "type": "button",
                              "text": {
                                  "type": "plain_text",
                                  "text": "Acknowledge"
                              },
                              "value": "ack"
                          }
                      ]
                  }
              ]"""
    send_message_to_destinations([], "", "", blocks=blocks)  # No destinations, no response


@pytest.mark.parametrize('sent, expected_minutes', [(None, 1), ('2019-09-26 18:37:25', 1), ('2019-09-26 18:10:25', 2),
                                                    ('2019-09-26 17:38:24', 5), ('2019-09-25 18:10:25', 5)])
def test_get_poll_minutes(sent, expected_minutes):
    from SlackV3 import get_poll_minutes

    # Set
    current = datetime(2019, 9, 26, 18, 38, 25)

    # Arrange
    minutes = get_poll_minutes(current, sent)

    # Assert
    assert minutes == expected_minutes


def test_edit_message(mocker):
    """
    Given:
        The text 'Boom', a threadID and known channel.

    When:
        Editing a message

    Then:
        Send a request to slack where the text includes the url footer, and valid channel ID.
    """
    import SlackV3
    # Set

    slack_response_mock = SlackResponse(
        client=None,
        http_verb='',
        api_url='',
        req_args={},
        headers={},
        status_code=200,
        data={
            'ok': True,
            'channel': 'C061EG9T2',
            'ts': '1629281551.001000',
            'text': 'Boom\nView it on: <https://www.eizelulz.com:8443/#/WarRoom/727>',
            'message': {
                'type': 'message',
                'subtype': 'bot_message',
                'text': 'Boom\nView it on: <https://www.eizelulz.com:8443/#/WarRoom/727>',
                'username': 'Cortex XSOAR',
                'icons': {
                    'image_48': 'https://s3-us-west-2.amazonaws.com/slack-files2/bot_icons/2021-06-29/2227534346388_48.png'
                },
                'bot_id': 'B01UZHGMQ9G'
            }
        }
    )

    expected_body = {
        'body': {
            'channel': 'C061EG9T2',
            'ts': '1629281551.001000',
            'text': 'Boom\nView it on: https://www.eizelulz.com:8443/#/WarRoom/727'
        }
    }

    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'args', return_value={'channel': "random", "threadID": "1629281551.001000", "message": "Boom"})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(SlackV3, 'send_slack_request_sync', return_value=slack_response_mock)

    # Arrange
    SlackV3.slack_edit_message()

    args = SlackV3.send_slack_request_sync.call_args.kwargs

    # Assert
    assert SlackV3.send_slack_request_sync.call_count == 1

    assert args == expected_body


def test_edit_message_not_valid_thread_id(mocker):
    """
    Given:
        The text 'Boom', an incorrect threadID and known channel.

    When:
        Editing a message

    Then:
        Send a request to slack where the text includes the url footer, and valid channel ID.
    """
    import SlackV3
    # Set

    err_response: SlackResponse = SlackResponse(api_url='', client=None, http_verb='POST',
                                                req_args={},
                                                data={'ok': False, 'error': 'message_not_found'},
                                                status_code=429,
                                                headers={})
    api_call = SlackApiError('The request to the Slack API failed.', err_response)

    expected_body = (
        "The request to the Slack API failed.\n"
        "The server responded with: {'ok': False, 'error': 'message_not_found'}"
    )
    link = 'https://www.eizelulz.com:8443/#/WarRoom/727'
    mocker.patch.object(demisto, 'investigation', return_value={'type': 1})
    mocker.patch.object(demisto, 'demistoUrls', return_value={'warRoom': link})
    mocker.patch.object(demisto, 'args', return_value={'channel': "random", "threadID": "162928", "message": "Boom"})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())

    # Arrange
    with pytest.raises(InterruptedError):
        SlackV3.slack_edit_message()

    err_msg = return_error_mock.call_args[0][0]

    # Assert
    assert err_msg == expected_body


def test_pin_message(mocker):
    """
     Given:
        The a valid threadID and known channel.

    When:
        Pinning a message

    Then:
        Send a request to slack where message is successfully pinned.
    """
    import SlackV3
    # Set

    slack_response_mock = {
        'ok': True
    }

    expected_body = {
        'body': {
            'channel': 'C061EG9T2',
            'timestamp': '1629281551.001000'
        }
    }

    mocker.patch.object(demisto, 'investigation', return_value={'type': 1})
    mocker.patch.object(demisto, 'args', return_value={'channel': "random", "threadID": "1629281551.001000"})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(SlackV3, 'send_slack_request_sync', return_value=slack_response_mock)

    # Arrange
    SlackV3.pin_message()

    args = SlackV3.send_slack_request_sync.call_args.kwargs

    # Assert
    assert SlackV3.send_slack_request_sync.call_count == 1

    assert args == expected_body


def test_pin_message_invalid_thread_id(mocker):
    """
     Given:
        The an invalid threadID and known channel.

    When:
        Pinning a message.

    Then:
        Send a request to slack where an error message is returned indicating the message could not
        be found.
    """
    import SlackV3
    # Set

    err_response: SlackResponse = SlackResponse(api_url='', client=None, http_verb='POST',
                                                req_args={},
                                                data={'ok': False, 'error': 'message_not_found'},
                                                status_code=429,
                                                headers={})
    api_call = SlackApiError('The request to the Slack API failed.', err_response)

    expected_body = (
        "The request to the Slack API failed.\n"
        "The server responded with: {'ok': False, 'error': 'message_not_found'}"
    )

    mocker.patch.object(demisto, 'investigation', return_value={'type': 1})
    mocker.patch.object(demisto, 'args', return_value={'channel': "random", "threadID": "1629281551.001000"})
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET, side_effect=InterruptedError())

    # Arrange
    with pytest.raises(InterruptedError):
        SlackV3.pin_message()

    err_msg = return_error_mock.call_args[0][0]

    # Assert
    assert err_msg == expected_body


TEST_BANK_MSG = [
    (INBOUND_MESSAGE_FROM_BOT, True),
    (INBOUND_MESSAGE_FROM_USER, False),
    (INBOUND_MESSAGE_FROM_BOT_WITH_BOT_ID, True),
    (INBOUND_EVENT_MESSAGE, False),
    (INBOUND_MESSAGE_FROM_BOT_WITHOUT_USER_ID, True),
    (SIMPLE_USER_MESSAGE, False)
]


@pytest.mark.parametrize('message, expected_response', TEST_BANK_MSG)
def test_is_bot_message(message, expected_response):
    """
    Given:
        Test Case 1 - A message from a bot
        Test Case 2 - A message from a user
        Test Case 3 - A message from a bot, but only containing a bot id which matches our bot id.
        Test Case 4 - A message from a user which is a reply to an action.
        Test Case 4 - A message from a bot without bot_msg as a subtype but also without user_id.
    When:
        Determining if the message is from a bot
    Then:
        Test Case 1 - Will determine True
        Test Case 2 - Will determine False
        Test Case 3 - Will determine True
        Test Case 4 - Will determine False
        Test Case 5 - Will determine True
    """
    import SlackV3
    SlackV3.BOT_ID = 'W12345678'

    result = SlackV3.is_bot_message(message)
    assert result is expected_response


UNEXPIRED_TIMESTAMP = 999999999999999999
EXPIRED_TIMESTAMP = 0000000000000000000
TEST_BANK_CONTEXT = [
    (UNEXPIRED_TIMESTAMP, False, {
        'mirrors': MIRRORS,
        'users': USERS,
        'conversations': CONVERSATIONS,
        'bot_id': 'W12345678'
    }),
    (EXPIRED_TIMESTAMP, False, {}),
    (UNEXPIRED_TIMESTAMP, True, {})
]


@pytest.mark.parametrize('expiry_time, force_refresh, cached_context', TEST_BANK_CONTEXT)
def test_fetch_context(mocker, monkeypatch, expiry_time, force_refresh, cached_context):
    """
    Given:
        Test Case 1 - Un-expired cache
        Test Case 2 - Expired cache
        Test Case 3 - Force set to True
    When:
        Retrieving either the cached, or un-cached context
    Then:
        Test Case 1 - The cache should be the same as what the existing cache is.
        Test Case 2 - The stored cache should be overwritten with the updated cache
        Test Case 3 - The cache is unexpired, but should refresh anyways.

    """
    import SlackV3
    from datetime import datetime
    back_to_the_future_now = datetime(2015, 10, 21, 7, 28, 0)
    datetime_mock = MagicMock(wraps=datetime)
    datetime_mock.now.return_value = back_to_the_future_now
    monkeypatch.setattr(__name__ + '.datetime', datetime_mock)

    SlackV3.CACHE_EXPIRY = expiry_time
    SlackV3.CACHED_INTEGRATION_CONTEXT = cached_context
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)

    result = SlackV3.fetch_context(force_refresh=force_refresh)

    assert result == INTEGRATION_CONTEXT  # noqa: F821


CREATED_CHANNEL_TESTBANK = [
    ('Channel123', 'itsamemario', {}, 1),
    ('Channel123', 'itsamemario', {
        'mirrors': json.dumps([])}, 1),
    ('Channel123', 'itsamemario', {
        'mirrors': json.dumps([
            {'channel_id': 'NotChannel123'}])}, 1),
    ('Channel123', 'itsamemario', {
        'mirrors': json.dumps([
            {'channel_id': 'NotChannel123'},
            {'channel_id': 'StillNotChannel123'},
            {'channel_id': 'Channel123'}])}, 0)
]


@pytest.mark.parametrize('channel_id, creator, cached_context, expected_result', CREATED_CHANNEL_TESTBANK)
def test_handle_newly_created_channel(mocker, channel_id, creator, cached_context, expected_result):
    """
    Given:
        Test Case 1 - Empty Cached Integration Context
        Test Case 2 - Cached Integration Context with the mirror key, but no values
        Test Case 3 - Cached Integration Context with the mirror key, but with no matching channel
        Test Case 4 - Cached Integration Context with the mirror key, but with a matching channel
    When:
        Receiving a `channel_created` event.
    Then:
        Test Case 1 - The cache should be refreshed
        Test Case 2 - Debug statement should indicate that no mirrors are in the cache and refresh the cache.
        Test Case 3 - Debug statement should say that channel was not found and cache is being refreshed
        Test Case 4 - Debug statement should say that a channel was found and the cache does not need to be refreshed
    """
    import SlackV3

    SlackV3.BOT_ID = 'itsamemario'
    SlackV3.CACHED_INTEGRATION_CONTEXT = cached_context
    SlackV3.CACHE_EXPIRY = 0

    mocker.patch.object(demisto, 'debug')

    SlackV3.handle_newly_created_channel(creator=creator, channel=channel_id)

    assert len(demisto.debug.mock_calls) == expected_result


CHANNEL_ID_BANK = [
    ('DthisisaDM', True, True),
    ('ThisisnotaDM', True, False),
    ('DthisisaDM', False, False),
    ('ThisisnotaDM', False, False)
]


@pytest.mark.parametrize('channel_id, enable_dm, expected_result', CHANNEL_ID_BANK)
def test_is_dm(channel_id, enable_dm, expected_result):
    """
    Given:
        Test Case 1 - A channel ID which starts with D and ENABLE_DM is True
        Test Case 2 - A channel ID which does not start with D and ENABLE_DM is True
        Test Case 3 - A channel ID which starts with D and ENABLE_DM is False
        Test Case 4 - A channel ID which does not start with D and ENABLE_DM is False
    When:
        Checking if a channel ID is actually a DM
    Then:
        Test Case 1 - is_dm should return True indicating it is a DM
        Test Case 2 - is_dm should return False indicating it is not a DM
        Test Case 3 - is_dm should return False indicating it is not a DM
        Test Case 4 - is_dm should return False indicating it is not a DM
    """
    import SlackV3

    SlackV3.ENABLE_DM = enable_dm
    result = SlackV3.is_dm(channel=channel_id)

    assert result == expected_result


MOCK_USER = AsyncSlackResponse(
    data=INBOUND_MESSAGE_FROM_USER,
    api_url='',
    client=AsyncMock(),
    headers={},
    http_verb='GET',
    req_args={},
    status_code=200

)
MOCK_INTEGRATION_CONTEXT = [
    {},
    {
        'mirrors': json.dumps([
            {
                'channel_id': 'NotChannel123'
            },
            {
                'channel_id': 'StillNotChannel123'
            }
        ])
    },
    {
        'mirrors': json.dumps([
            {
                'channel_id': 'NotChannel123'
            },
            {
                'channel_id': 'StillNotChannel123'
            },
            {
                'channel_id': 'Channel123',
                'mirror_direction': 'FromDemisto'
            }
        ])
    },
    {
        'mirrors': json.dumps([
            {
                'channel_id': 'NotChannel123',
                'mirror_direction': 'ToDemisto',
                'mirrored': False,
                'investigation_id': 123,
                'mirror_type': 'mirror I guess',
                'auto_close': False,
                'mirror_to': 'sometext'
            },
            {
                'channel_id': 'Channel123',
                'mirror_direction': 'ToDemisto',
                'mirrored': True,
                'investigation_id': 123,
                'mirror_type': 'mirror I guess',
                'auto_close': False,
                'mirror_to': 'sometext'
            }
        ])
    },
    {
        'mirrors': json.dumps([
            {
                'channel_id': 'NotChannel123',
                'mirror_direction': 'ToDemisto',
                'mirrored': False,
                'investigation_id': 123,
                'mirror_type': 'mirror I guess',
                'auto_close': False,
                'mirror_to': 'sometext'
            },
            {
                'channel_id': 'Channel123',
                'mirror_direction': 'ToDemisto',
                'mirrored': False,
                'investigation_id': 123,
                'mirror_type': 'mirror I guess',
                'auto_close': False,
                'mirror_to': 'sometext'
            }
        ])
    }
]


MIRRORS_TEST_BANK = [
    ('Channel123', 'Test text', MOCK_USER, 0,
     MOCK_INTEGRATION_CONTEXT[0]),
    ('Channel123', 'Test text', MOCK_USER, 0,
     MOCK_INTEGRATION_CONTEXT[1]),
    ('Channel123', 'Test text', MOCK_USER, 0,
     MOCK_INTEGRATION_CONTEXT[2]),
    ('Channel123', 'Test text', MOCK_USER, 0,
     MOCK_INTEGRATION_CONTEXT[3]),
    ('Channel123', 'Test text', MOCK_USER, 3,
     MOCK_INTEGRATION_CONTEXT[4])
]


@pytest.mark.asyncio
@pytest.mark.parametrize('channel_id, text, user, expected_result, context', MIRRORS_TEST_BANK)
async def test_process_mirror(mocker, channel_id, text, user, expected_result, context):
    """
    Given:
        Test Case 1 - A valid channel_id, text, and user, but with an empty cached integration context.
        Test Case 2 - A valid channel_id, text, and user, but channel ID is not in a mirror.
        Test Case 3 - A valid channel_id, text, and user, where channel ID is in a mirror, but mirror type is FromDemisto.
        Test Case 4 - A valid channel_id, text, and user, where channel ID is in a mirror, but it has already been mirrored
        Test Case 5 - A valid channel_id, text, and user, where channel ID is in a mirror, and it needs to be mirrored
    When:
        A mirror type message event is ingested
    Then:
        Test Case 1 - Should exit gracefully and write a debug log indicating there are no mirrors found.
        Test Case 2 - Should exit gracefully and write a debug log indicating a Generic Message was received.
        Test Case 3 - Should exit gracefully and write a debug log indicating a mirror was found, but it's mirror out only
        Test Case 4 - Should send the message to the war room of the matching incident.
        Test Case 5 - Should send the message to the war room of the matching incident and mark the investigation as mirrored.
    """
    import SlackV3

    SlackV3.CACHE_EXPIRY = UNEXPIRED_TIMESTAMP
    SlackV3.CACHED_INTEGRATION_CONTEXT = context
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'mirrorInvestigation')
    mocker.patch.object(SlackV3, 'handle_text')

    await SlackV3.process_mirror(channel_id=channel_id, text=text, user=user)

    assert len(demisto.debug.mock_calls) == expected_result


ENTITLEMENT_STRING_TEST_BANK = [
    ('This is some text without an entitlement.', MOCK_USER, ''),
    ('This is some text with an entitlement. 4404dae8-2d45-46bd-85fa-64779c12abe8@22|43 goodbye', MOCK_USER,
     'Thank you for your response.'),

]


@pytest.mark.parametrize('text, user, expected_result', ENTITLEMENT_STRING_TEST_BANK)
def test_search_text_for_entitlement(text, user, expected_result):
    """
    Given:
        Test Case 1 - Text not containing an entitlement string.
        Test Case 2 - Text containing an entitlement string.
    When:
        Determining if a text contains an entitlement.
    Then:
        Test Case 1 - No entitlement is found so the returned string is empty
        Test Case 2 - An entitlement is found so the returned string is the default "Thank you for your response"
    """
    import SlackV3

    result = SlackV3.search_text_for_entitlement(text=text, user=user)

    assert result == expected_result


ENTITLEMENT_REPLY_TEST_BANK = [
    ('This is an entitlement reply', 'This is an entitlement reply'),
    ('This is an entitlement reply {user}', 'This is an entitlement reply <@Dingus>'),
    ('This is an entitlement reply {response}', 'This is an entitlement reply Done'),
    ('This is an entitlement reply {response} - {user}', 'This is an entitlement reply Done - <@Dingus>')
]


@pytest.mark.asyncio
@pytest.mark.parametrize('entitlement_reply, expected_text', ENTITLEMENT_REPLY_TEST_BANK)
async def test_process_entitlement_reply(mocker, entitlement_reply, expected_text):
    """
    Given:
        Test Case 1 - An entitlement reply without a user or response placeholder
        Test Case 2 - An entitlement reply with a user placeholder
        Test Case 3 - An entitlement reply with a response placeholder
        Test Case 4 - An entitlement reply with a user and response placeholder
    When:
        Processing and sending the entitlement reply.
    Then:
        Test Case 1 - A request made to chat.Update where text is the reply without a user or response placeholder
        Test Case 2 - A request made to chat.Update where text is the reply with a user and without a response placeholder
        Test Case 3 - A request made to chat.Update where text is the reply without a user and with a response placeholder
        Test Case 4 - A request made to chat.Update where text is the reply with a user and with a response placeholder
    """
    import SlackV3

    mocker.patch.object(SlackV3, 'send_slack_request_async')

    await SlackV3.process_entitlement_reply(
        entitlement_reply=entitlement_reply,
        user_id='Dingus',
        action_text='Done',
        channel='DootDoot',
        message_ts='1234.5'
    )

    assert SlackV3.send_slack_request_async.mock_calls[0].kwargs.get('body').get('text') == expected_text


def test_handle_tags_in_message_sync_url(mocker):
    from SlackV3 import handle_tags_in_message_sync

    # Set
    def api_call(method: str, http_verb: str = 'POST', file: str = None, params=None, json=None, data=None):
        if method == 'users.list':
            return {'members': js.loads(USERS)}
        return None

    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(slack_sdk.WebClient, 'api_call', side_effect=api_call)

    user_exists_message_url = "Hello <@spengler>! <https://google.com|This message is a link to google.>"

    user_message_exists_in_url_result = handle_tags_in_message_sync(user_exists_message_url)

    # Assert

    assert user_message_exists_in_url_result == 'Hello <@U012A3CDE>! <https://google.com|This message is a link to google.>'


def test_remove_channel_from_context(mocker):
    """
    Given:
        An integration context dict containing a known channel ID to remove
    When:
        Removing a deleted channel from the context
    Then:
        Assert that the channel ID of the channel to remove is no longer found in the context
    """
    from SlackV3 import remove_channel_from_context
    testing_context = {'conversations': "["
                                        "{\"name\": \"1657185964826\", \"id\": \"C03NF1QTK38\"},"
                                        "{\"name\": \"1657186151481\", \"id\": \"C03NF23NFRU\"},"
                                        "{\"name\": \"1657186333246\", \"id\": \"C03NMJJTJ75\"}"
                                        "]"}
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    remove_channel_from_context(channel_id="C03NF1QTK38", integration_context=testing_context)

    updated_context = demisto.setIntegrationContext.call_args[0][0]
    new_conversations = json.loads(updated_context.get('conversations', {}))
    for new_conversation in new_conversations:
        assert new_conversation.get('id') != 'C03NF1QTK38'


def test_slack_get_integration_context(mocker):
    """
    Given:
        An integration context dict
    When:
        Fetching statistics about the context
    Then:
        Assert that the human-readable of the result is correct
    """
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'results')
    from SlackV3 import slack_get_integration_context

    expected_results = ('### Long Running Context Statistics\n'
                        '|Conversations Count|Conversations Size In Bytes|Mirror Size In '
                        'Bytes|Mirrors Count|Users Count|Users Size In Bytes|\n'
                        '|---|---|---|---|---|---|\n'
                        '| 2 | 1706 | 1397 | 5 | 2 | 1843 |\n')
    slack_get_integration_context()

    assert demisto.results.mock_calls[0][1][0]['HumanReadable'] == expected_results


def test_search_slack_users(mocker):
    """
    Given:
        A list of users containing some invalid values
    When:
        Searching for a user
    Then:
        Assert the returned list contains no null values
    """
    import SlackV3
    from SlackV3 import search_slack_users

    mocker.patch.object(SlackV3, 'get_user_by_name', return_value={"ValidUser"})

    users = ['', 'ValidUser', None]
    results = search_slack_users(users=users)

    assert results == [{'ValidUser'}]


def test_slack_get_integration_context_statistics(mocker):
    """
    Given:
        An integration context containing mirrors, conversations, and channels.
    When:
        Generating a report of the integration context statistics.
    Then:
        Assert that the value returned matches what we expect to receive back.
    """
    mocker.patch.object(demisto, 'getIntegrationContext', side_effect=get_integration_context)
    from SlackV3 import slack_get_integration_context_statistics

    expected_results = {
        'Mirrors Count': 5,
        'Mirror Size In Bytes': 1397,
        'Conversations Count': 2,
        'Conversations Size In Bytes': 1706,
        'Users Count': 2,
        'Users Size In Bytes': 1843
    }

    integration_statistics, _ = slack_get_integration_context_statistics()

    assert integration_statistics == expected_results


def test_check_for_unanswered_questions(mocker):
    """
    Given:
        Integration Context containing one expired question.
    When:
        Checking to see if a question is unanswered.
    Then:
        Assert that the question is seen as expired and is then removed from the updated context.
    """
    import SlackV3
    mocker.patch.object(SlackV3, 'fetch_context', side_effect=get_integration_context)
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)

    questions = [{
        'thread': 'cool',
        'entitlement': 'e95cb5a1-e394-4bc5-8ce0-508973aaf298@22|43',
        'reply': 'Thanks bro',
        'expiry': '2019-09-26 18:38:25',
        'sent': '2019-09-26 18:38:25',
        'default_response': 'NoResponse'
    }]

    set_integration_context({
        'mirrors': MIRRORS,
        'users': USERS,
        'conversations': CONVERSATIONS,
        'bot_id': 'W12345678',
        'questions': js.dumps(questions)
    })

    SlackV3.check_for_unanswered_questions()
    updated_context = demisto.setIntegrationContext.call_args[0][0]
    total_questions = js.loads(updated_context.get('questions'))

    assert len(total_questions) == 0


def test_list_channels(mocker):
    """
    Given:
        A list of channels.
    When:
        Listing Channels.
    Assert:
        fields match and are listed.
    """
    import SlackV3
    slack_response_mock = {
        'ok': True,
        'channels': json.loads(CHANNELS)}
    expected_human_readable = (
        '### Channels list for None with filter None\n'
        '|Created|Creator|ID|Name|Purpose|\n|---|---|---|---|---|\n'
        '| 1666361240 | spengler | C0475674L3Z | general | This is the '
        'one channel that will always include everyone. It’s a great '  # noqa: RUF001
        'spot for announcements and team-wide conversations. |\n'
    )
    mocker.patch.object(SlackV3, 'send_slack_request_sync', side_effect=[slack_response_mock, {'user': js.loads(USERS)[0]}])
    mocker.patch.object(demisto, 'args', return_value={'channel_id': 1, 'public_channel': 'public_channel', 'limit': 1})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    # mocker.patch.object(SlackV3, 'send_slack_request_sync', side_effect=slack_response_mock)
    SlackV3.list_channels()
    assert demisto.results.called
    assert demisto.results.call_args[0][0]['HumanReadable'] == expected_human_readable
    assert demisto.results.call_args[0][0]['ContentsFormat'] == 'json'


def test_conversation_history(mocker):
    """
    Given:
        A set of conversations.
    When:
        Listing conversation history.
    Assert:
        Conversations are returned.
    """
    import SlackV3
    slack_response_mock = {
        'ok': True,
        'messages': json.loads(MESSAGES)}
    mocker.patch.object(SlackV3, 'send_slack_request_sync',
                        side_effect=[slack_response_mock, {'user': js.loads(USERS)[0]},
                                     {'user': js.loads(USERS)[0]}])
    mocker.patch.object(demisto, 'args', return_value={'channel_id': 1, 'conversation_id': 1, 'limit': 1})
    mocker.patch.object(demisto, 'setIntegrationContext', side_effect=set_integration_context)
    mocker.patch.object(demisto, 'results')

    SlackV3.conversation_history()

    assert demisto.results.call_args[0][0]['HumanReadable'] == '### Channel details from Channel ID ' \
                                                               '- 1\n|FullName|HasReplies|Name|Text|ThreadTimeStamp' \
                                                               '|TimeStamp|Type|UserId|\n|---|---|---|---|---|' \
                                                               '---|---|---|\n| spengler | No | spengler | There' \
                                                               ' are two types of people in this world, those' \
                                                               ' who can extrapolate from incomplete data... | N/A ' \
                                                               '| 1690479909.804939 | message | U047D5QSZD4 |\n|' \
                                                               ' spengler | Yes | spengler | Give me a fresh dad joke' \
                                                               ' | 1690479887.647239 | 1690479887.647239 | message ' \
                                                               '| U047D5QSZD4 |\n'
    assert demisto.results.call_args[0][0]['ContentsFormat'] == 'json'


@pytest.mark.parametrize('raw, output', [
    ("""
    key1:value1
    
    
    key2: value2
    
    """, {'key1': 'value1', 'key2': 'value2'}),
    ('key1: value1', {'key1': 'value1'}), ("""
    
    
    """, {})

])
def test_parse_common_channels(raw, output):
    assert parse_common_channels(raw) == output


def test_parse_common_channels_error(mocker):
    with pytest.raises(ValueError) as e:
        mocker.patch.object(demisto, 'error')
        parse_common_channels('bad input')
    assert "Invalid common_channels parameter value." in str(e.value)


def test_conversation_replies(mocker):
    """
    Given:
        A conversation with replies
    When:
        Looking for conversations with replies
    Assert:
        Conversations has replies.
    """
    import SlackV3
    mocker.patch.object(slack_sdk.WebClient, 'api_call')
    mocker.patch.object(demisto, 'args', return_value={'channel_id': 1, 'thread_timestamp': 1234, 'limit': 1})
    mocker.patch.object(demisto, 'results')
    slack_response_mock = {
        'ok': True,
        'messages': json.loads(MESSAGES)}
    mocker.patch.object(SlackV3, 'send_slack_request_sync',
                        side_effect=[slack_response_mock,
                                     {'user': js.loads(USERS)[0]},
                                     {'user': js.loads(USERS)[0]}])
    SlackV3.conversation_replies()
    assert demisto.results.call_args[0][0]['HumanReadable'] == '### Channel details from Channel ID' \
                                                               ' - 1\n|FullName|IsParent|Name|Text|ThreadTimeStamp' \
                                                               '|TimeStamp|Type|UserId|\n|---|---|---|---|---|---' \
                                                               '|---|---|\n| spengler | No | spengler | There are ' \
                                                               'two types of people in this world, those who can ' \
                                                               'extrapolate from incomplete data... | ' \
                                                               ' | 1690479909.804939 | message | U047D5QSZD4 ' \
                                                               '|\n| spengler | Yes | spengler | Give me a fresh dad' \
                                                               ' joke | 1690479887.647239 | 1690479887.647239 | message |' \
                                                               ' U047D5QSZD4 |\n'
    assert demisto.results.call_args[0][0]['ContentsFormat'] == 'json'


SAMPLE_PAYLOAD = json.loads(
    load_test_data('./test_data/entitlement_response_payload.txt')
)


@pytest.fixture
async def client_session():
    session = aiohttp.ClientSession()
    yield session
    await session.close()


@pytest.mark.asyncio
async def test_listen(client_session):
    """
    Unit test for the `listen` function in the `SlackV3` module. This test case verifies that the function handles
    Slack events correctly.
    The test uses a mocked SocketModeRequest object and a mocked SocketModeClient object. It also mocks the Slack API
    call and the `demisto.debug` method.
    The test sets a return value for the `get_user_details` method, which is used in the function. It also sets a mock
    response for the Slack API call.
    The function is expected to call the `demisto.debug` method once with the message "Starting to process message",
    and make a Slack API call with the expected JSON payload.
    """
    from unittest import mock
    from slack_sdk.socket_mode.aiohttp import SocketModeClient
    from slack_sdk.socket_mode.request import SocketModeRequest

    import SlackV3

    default_envelope_id = "SOMEID"

    expected_content = ('{"values": {"checkboxes_0": {"checkboxes-action": {"type": "checkboxes", '
                        '"selected_options": [{"text": {"type": "plain_text", "text": "*Option 3*", '
                        '"emoji": true}, "value": "value-2"}]}}, "timepicker_1": {"timepicker1": '
                        '{"type": "timepicker", "selected_time": "06:00"}}}, "xsoar-button-submit": '
                        '"Successful"}')
    req = SocketModeRequest(type='event', payload=SAMPLE_PAYLOAD, envelope_id=default_envelope_id)
    client = mock.MagicMock(spec=SocketModeClient)
    with mock.patch.object(SlackV3, 'get_user_details') as mock_get_user_details, \
        mock.patch.object(demisto, 'debug') as mock_debug, \
        mock.patch.object(requests, 'post') as mock_send_slack_request, \
        mock.patch.object(SlackV3, 'reset_listener_health'), \
            mock.patch.object(demisto, 'handleEntitlementForUser') as mock_result:

        # Set the return value of the mocked get_user_details function
        mock_user = {'id': 'mock_user_id', 'name': 'mock_user'}
        mock_get_user_details.return_value = mock_user

        mock_send_slack_request_response = {'ok': True}
        mock_send_slack_request.return_value.json.return_value = mock_send_slack_request_response

        await SlackV3.listen(client, req)

        # Here we verify the call was processed at all.
        assert mock_debug.call_count == 2
        assert mock_send_slack_request.call_args[1].get('json') == {'text': 'reply to 3', 'replace_original': True}

        # Extract the specific information which should be found in the entitlement
        result_incident_id = mock_result.call_args[0][0]
        result_entitlement = mock_result.call_args[0][1]
        test_result_content = mock_result.call_args[0][3]

        assert result_incident_id == '3'
        assert result_entitlement == '326a8a51-3dbd-4b07-8662-d36bfa9509fb'
        assert test_result_content == expected_content


class TestGetWarRoomURL:

    def test_get_war_room_url_with_xsiam_from_incident_war_room(self, mocker):
        url = "https://example.com/WarRoom/INCIDENT-2930"
        expected_war_room_url = "https://example.com/incidents/war_room?caseId=2930"
        mocker.patch('SlackV3.is_xsiam', return_value=True)
        mocker.patch.dict(demisto.callingContext, {'context': {'Inv': {'id': 'INCIDENT-2930'}}})

        assert get_war_room_url(url) == expected_war_room_url

    def test_get_war_room_url_without_xsiam_from_incident_war_room(self, mocker):
        url = "https://example.com/WarRoom/INCIDENT-2930"
        mocker.patch('SlackV3.is_xsiam', return_value=False)
        expected_war_room_url = "https://example.com/WarRoom/INCIDENT-2930"
        assert get_war_room_url(url) == expected_war_room_url

    def test_get_war_room_url_with_xsiam_from_alert_war_room(self, mocker):
        url = "https://example.com/WarRoom/ALERT-1234"
        mocker.patch('SlackV3.is_xsiam', return_value=True)
        mocker.patch.dict(demisto.callingContext, {'context': {'Inv': {'id': '1234'}}})
        expected_war_room_url = \
            "https://example.com/incidents/alerts_and_insights?caseId=1234&action:openAlertDetails=1234-warRoom"
        assert get_war_room_url(url) == expected_war_room_url


def test_send_file_api_exception(mocker):
    """
    Given:
        - A mocked, faulty Slack API response.
    When:
        - Calling the slack_send_file function.
    Then:
        - Assert readable exception is raised.
    """
    from SlackV3 import slack_send_file
    # Set
    mocker.patch('SlackV3.slack_send_request', side_effect=SlackApiError('The request to the Slack API failed. (url: https://slack.com/api/files.upload)',
                                                                         {'ok': False, 'error': 'method_deprecated'}))

    # Check that function raises DemistoException
    with pytest.raises(DemistoException) as e:
        slack_send_file('channel', _entry_id='123', _comment='Here is a file!')
    assert str(e.value) == 'Failed to send file: test.txt to Slack. The method has been deprecated.'


def test_validate_slack_request_args():
    """
    Given:
        - Invalid Slack API request arguments.
    When:
        - Calling the validate_slack_request_args function.
    Then:
        - Assert ValueError is raised.
    """
    from SlackV3 import validate_slack_request_args

    with pytest.raises(ValueError) as e:
        validate_slack_request_args(http_verb='HI', method='chat.postMessage', file_upload_params=None)
    assert str(e.value) == 'Invalid http_verb: HI. Allowed values: POST, GET.'
